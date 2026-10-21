//go:build windows

package winengine

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/AyoubAchour/net-switch/internal/winhandle"
	"golang.org/x/sys/windows"
)

const pipeOSFileDuplexEnv = "NETSWITCH_PIPE_OSFILE_DUPLEX"

// pipeDuplex sends n bytes each way at the same time, in 4 KiB writes, and
// checks every byte. Each end reads and writes concurrently, as the protocol
// server does.
func pipeDuplex(server, client io.ReadWriter, n int) error {
	pattern := func(seed byte, i int) byte { return byte(i*31) ^ seed }
	errs := make(chan error, 4)
	pump := func(w io.Writer, seed byte) {
		buf := make([]byte, n)
		for i := range buf {
			buf[i] = pattern(seed, i)
		}
		for sent := 0; sent < n; sent += 4096 {
			if _, err := w.Write(buf[sent:min(sent+4096, n)]); err != nil {
				errs <- err
				return
			}
		}
		errs <- nil
	}
	drain := func(r io.Reader, seed byte) {
		buf := make([]byte, n)
		_, err := io.ReadFull(r, buf)
		for i := 0; err == nil && i < n; i++ {
			if buf[i] != pattern(seed, i) {
				err = fmt.Errorf("byte %d is %#x, want %#x", i, buf[i], pattern(seed, i))
			}
		}
		errs <- err
	}
	go pump(server, 1)
	go drain(client, 1)
	go pump(client, 2)
	go drain(server, 2)
	for range 4 {
		if err := <-errs; err != nil {
			return err
		}
	}
	return nil
}

// osFileDuplexChild is the old path, as a negative control: the same duplex
// traffic through two os.File pipe ends. Run in its own process so a race
// report there cannot fail or hide anything in the parent.
func osFileDuplexChild() error {
	name := fmt.Sprintf(`\\.\pipe\netswitch-osfile-duplex-%d`, os.Getpid())
	path, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return err
	}
	server, err := windows.CreateNamedPipe(path, windows.PIPE_ACCESS_DUPLEX|windows.FILE_FLAG_OVERLAPPED|windows.FILE_FLAG_FIRST_PIPE_INSTANCE,
		windows.PIPE_TYPE_BYTE|windows.PIPE_READMODE_BYTE|windows.PIPE_REJECT_REMOTE_CLIENTS, 1, 64<<10, 64<<10, 0, nil)
	if err != nil {
		return err
	}
	client, err := windows.CreateFile(path, windows.GENERIC_READ|windows.GENERIC_WRITE, 0, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_OVERLAPPED, 0)
	if err != nil {
		windows.CloseHandle(server)
		return err
	}
	serverFile, clientFile := os.NewFile(uintptr(server), name), os.NewFile(uintptr(client), name)
	defer serverFile.Close()
	defer clientFile.Close()
	return pipeDuplex(serverFile, clientFile, 1<<20)
}

// TestEnginePipeFullDuplex sends 1 MiB each way at once through a real
// accepted engine pipe, and closes a connection with a read pending. Under
// -race this is the regression for Go 1.27.3's unsynchronized pipe offset;
// the os.File negative control must still be reported by the race detector.
func TestEnginePipeFullDuplex(t *testing.T) {
	hosted(t) // fixed production pipe: disposable hosted runner only
	listener, err := ListenPipe(EnginePipe, true)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	connect := func(label string) (io.ReadWriteCloser, io.ReadWriteCloser) {
		accepted := make(chan io.ReadWriteCloser, 1)
		failed := make(chan error, 1)
		go func() {
			conn, err := listener.Accept(ctx)
			if err != nil {
				failed <- err
				return
			}
			accepted <- conn
		}()
		ptr, _ := windows.UTF16PtrFromString(EnginePipe)
		h, err := windows.CreateFile(ptr, windows.GENERIC_READ|windows.GENERIC_WRITE, 0, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_OVERLAPPED, 0)
		if err != nil {
			t.Fatal(err)
		}
		// The test client uses the same connection type, so its own
		// concurrent reads and writes cannot trip the os.File race either.
		client, err := newPipeConn(winhandle.Open(h, "duplex pipe client "+label), EnginePipe)
		if err != nil {
			t.Fatal(err)
		}
		select {
		case conn := <-accepted:
			return conn, client
		case err := <-failed:
			client.Close()
			t.Fatal(err)
		}
		return nil, nil
	}

	server, client := connect("traffic")
	began := time.Now()
	if err := pipeDuplex(server, client, 1<<20); err != nil {
		t.Fatalf("full-duplex engine pipe traffic: %v", err)
	}
	t.Logf("engine pipe full duplex: 1 MiB each way in 4 KiB writes, exact bytes, %s", time.Since(began).Round(time.Millisecond))
	// The client hanging up is a clean end of stream for the server.
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
	var b [1]byte
	if n, err := server.Read(b[:]); n != 0 || !errors.Is(err, io.EOF) {
		t.Fatalf("read after the client closed = %d, %v; want io.EOF", n, err)
	}
	if err := server.Close(); err != nil {
		t.Fatal(err)
	}

	// Close must cancel a pending read, wait for the kernel, and then fail
	// later operations without touching the closed handle.
	server, client = connect("close")
	defer client.Close()
	readDone := make(chan error, 1)
	go func() {
		var b [16]byte
		_, err := server.Read(b[:])
		readDone <- err
	}()
	time.Sleep(50 * time.Millisecond) // let the read reach the kernel; the assertion below does not depend on it
	closed := time.Now()
	if err := server.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-readDone:
		if !errors.Is(err, os.ErrClosed) {
			t.Fatalf("pending read after Close returned %v; want os.ErrClosed", err)
		}
		t.Logf("pending read cancelled by Close in %s", time.Since(closed).Round(time.Microsecond))
	case <-time.After(5 * time.Second):
		t.Fatal("Close did not cancel the pending read")
	}
	if _, err := server.Write([]byte("late")); !errors.Is(err, os.ErrClosed) {
		t.Fatalf("write after Close returned %v; want os.ErrClosed", err)
	}

	// Negative control for the old path, in a child process.
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(exe, "-test.run=^$")
	cmd.Env = append(os.Environ(), pipeOSFileDuplexEnv+"=1")
	out, err := cmd.CombinedOutput()
	reported := strings.Contains(string(out), "WARNING: DATA RACE") && strings.Contains(string(out), "addOffset")
	t.Logf("os.File duplex control: race_build=%t exit_error=%v race_reported=%t old_would_pass=%t", raceEnabled, err, reported, !reported)
	if raceEnabled && !reported {
		t.Fatalf("the os.File negative control did not reproduce Go's pipe offset race; output:\n%s", out)
	}
	if !raceEnabled && err != nil {
		t.Fatalf("os.File duplex control failed without the race detector: %v\n%s", err, out)
	}
}
