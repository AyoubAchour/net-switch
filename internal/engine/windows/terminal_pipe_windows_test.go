//go:build windows

package winengine

import (
	"context"
	"encoding/json"
	"io"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"unsafe"

	"github.com/AyoubAchour/net-switch/internal/engine/flows"
	"github.com/AyoubAchour/net-switch/internal/engine/protocol"
	"github.com/AyoubAchour/net-switch/internal/winhandle"
	"github.com/AyoubAchour/net-switch/internal/wintun"
	"golang.org/x/sys/windows"
)

type terminalPipeObserver struct {
	io.ReadWriteCloser
	started, completed atomic.Int32
	// Only the protocol writer accesses these; the observer itself is owned
	// by Serve's goroutine. Retain and explicitly pin the payload until the
	// production File.Write has completed or drained cancellation.
	pending    []byte
	payloadPin runtime.Pinner
}

func (p *terminalPipeObserver) Write(b []byte) (int, error) {
	p.pending = b
	if len(b) != 0 {
		p.payloadPin.Pin(unsafe.SliceData(p.pending))
	}
	p.started.Add(1)
	// No test-owned stack OVERLAPPED: Go 1.27.3 internal/poll.FD.execIO
	// obtains operation from its heap pool and pins that operation plus the
	// payload before submission. waitIO/waitCanceled drain completion before
	// execIO unpins and File.Write returns. Exercise that production path.
	n, err := p.ReadWriteCloser.Write(p.pending)
	p.payloadPin.Unpin()
	p.pending = nil
	p.completed.Add(1)
	return n, err
}

func TestTerminalLossCancelsRealEnginePipeBlockedWrite(t *testing.T) {
	hosted(t) // fixed production pipe: disposable hosted runner only
	listener, err := ListenPipe(EnginePipe, true)
	if err != nil {
		t.Fatal(err)
	}
	closeListener := sync.OnceValue(listener.Close)
	defer closeListener()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ptr, err := windows.UTF16PtrFromString(EnginePipe)
	if err != nil {
		t.Fatal(err)
	}
	h, err := windows.CreateFile(ptr, windows.GENERIC_READ|windows.GENERIC_WRITE, 0, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_OVERLAPPED, 0)
	if err != nil {
		t.Fatal(err)
	}
	client := winhandle.NewFile(winhandle.Open(h, "terminal blocked pipe client"), EnginePipe)
	defer client.Close()
	if err := client.SetDeadline(time.Now().Add(8 * time.Second)); err != nil {
		t.Fatal(err)
	}
	conn, err := listener.Accept(ctx)
	if err != nil {
		t.Fatal(err)
	}
	observed := &terminalPipeObserver{ReadWriteCloser: conn}
	runtime := &tailTestRuntime{table: flows.New(flows.Defaults(), nil), first: make(chan struct{}), second: make(chan struct{})}
	s := protocol.New(runtime, runtime.table, nil)
	served := make(chan error, 1)
	go func() { served <- s.Serve(ctx, observed) }()
	enc, dec := json.NewEncoder(client), json.NewDecoder(client)
	if err := enc.Encode(protocol.Request{ID: "attach", Method: "attach", Instance: s.Instance}); err != nil {
		t.Fatal(err)
	}
	var reply protocol.Reply
	if err := dec.Decode(&reply); err != nil || reply.Error != "" {
		t.Fatal(reply, err)
	}
	// Keep this real, connected client open but stop reading. More than the
	// 64 KiB kernel buffer fits in the existing bounded event queue.
	oneByte, err := json.Marshal(protocol.Event{Type: "log", Message: "x"})
	if err != nil {
		t.Fatal(err)
	}
	event := protocol.Event{Type: "log", Message: strings.Repeat("x", 4096-len(oneByte))}
	encoded, err := json.Marshal(event)
	if err != nil || len(encoded)+1 != 4096 {
		t.Fatalf("event does not exactly fill a 4 KiB pipe block: bytes=%d err=%v", len(encoded)+1, err)
	}
	for range 1000 {
		s.Emit(event)
	}
	raw, err := client.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	peek := windows.NewLazySystemDLL("kernel32.dll").NewProc("PeekNamedPipe")
	var available uint32
	deadline := time.Now().Add(3 * time.Second)
	for {
		var peekErr error
		if err := raw.Control(func(fd uintptr) {
			ok, _, callErr := peek.Call(fd, 0, 0, 0, uintptr(unsafe.Pointer(&available)), 0)
			if ok == 0 {
				peekErr = callErr
			}
		}); err != nil {
			t.Fatal(err)
		}
		if peekErr != nil {
			t.Fatal(peekErr)
		}
		if available >= 64<<10 && observed.started.Load() == observed.completed.Load()+1 {
			completed := observed.completed.Load()
			time.Sleep(50 * time.Millisecond)
			if observed.completed.Load() == completed && observed.started.Load() == completed+1 {
				break
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("blocked native write precondition missing: queued=%d writes=%d/%d", available, observed.completed.Load(), observed.started.Load())
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Logf("client still connected; native queued bytes=%d, writes started/completed=%d/%d", available, observed.started.Load(), observed.completed.Load())
	loss := newAdapterLoss()
	loss.handle(wintun.ErrAdapterRemoved)
	started := time.Now()
	done := make(chan error, 1)
	go func() {
		done <- serveUntilStopped(context.Background(), shutdownTail{
			runtime: runtime, server: s, loss: loss, fatal: make(chan error, 1),
			cancel: cancel, closePipe: closeListener, join: func() { <-served },
			finalize: func() error { return nil }, release: func() error { return nil },
		})
	}()
	err = tailResult(t, done)
	elapsed := time.Since(started)
	if _, ok := err.(*AdapterLostError); !ok {
		t.Fatalf("blocked controller changed clean loss outcome: %v", err)
	}
	if elapsed < protocol.TerminalDeliveryTimeout || elapsed > protocol.TerminalDeliveryTimeout+time.Second {
		t.Fatalf("native pipe cancellation elapsed=%v", elapsed)
	}
	if observed.started.Load() != observed.completed.Load() {
		t.Fatal("Serve returned with native write still pending")
	}
	if runtime.stops.Load() != 1 {
		t.Fatal("blocked pipe changed cleanup count")
	}
}
