package lifecycle_test

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

type linuxWorker struct {
	pid  uint32
	fd   int
	mode string
	t    *testing.T
}

func (w *linuxWorker) id() uint32   { return w.pid }
func (w *linuxWorker) kind() string { return w.mode }
func (w *linuxWorker) close()       { unix.Close(w.fd) }
func (w *linuxWorker) alive() bool {
	fds := []unix.PollFd{{Fd: int32(w.fd), Events: unix.POLLIN}}
	for {
		n, err := unix.Poll(fds, 0)
		if errors.Is(err, unix.EINTR) {
			w.t.Logf("pidfd poll interrupted for %s/%d; reading process state again", w.mode, w.pid)
			continue
		}
		if err != nil {
			w.t.Fatalf("pidfd poll %s/%d fd=%d: %v", w.mode, w.pid, w.fd, err)
		}
		if n > 0 && fds[0].Revents&(unix.POLLIN|unix.POLLHUP) == 0 {
			w.t.Fatalf("unexpected pidfd events %s/%d: %#x", w.mode, w.pid, fds[0].Revents)
		}
		return n == 0
	}
}
func (w *linuxWorker) suspend() error { return unix.PidfdSendSignal(w.fd, unix.SIGSTOP, nil, 0) }
func findWorkers(t *testing.T, parent uint32, directory string) []workerRef {
	t.Helper()
	entries, err := os.ReadDir("/proc")
	if err != nil {
		t.Fatal(err)
	}
	var refs []workerRef
	for _, entry := range entries {
		pid, err := strconv.ParseUint(entry.Name(), 10, 32)
		if err != nil {
			continue
		}
		path := filepath.Join("/proc", entry.Name())
		b, err := os.ReadFile(filepath.Join(path, "stat"))
		if err != nil {
			continue
		}
		end := strings.LastIndex(string(b), ")")
		if end < 0 {
			continue
		}
		fields := strings.Fields(string(b[end+1:]))
		if len(fields) < 2 || fields[1] != strconv.FormatUint(uint64(parent), 10) {
			continue
		}
		exe, err := os.Readlink(filepath.Join(path, "exe"))
		if err != nil || exe != filepath.Join(directory, "netswitch-engine") {
			continue
		}
		command, err := os.ReadFile(filepath.Join(path, "cmdline"))
		if err != nil {
			continue
		}
		args := strings.Split(strings.TrimRight(string(command), "\x00"), "\x00")
		if len(args) != 3 || args[1] != "worker" || (args[2] != "network" && args[2] != "meters") {
			continue
		}
		fd, err := unix.PidfdOpen(int(pid), 0)
		if err != nil {
			continue
		}
		refs = append(refs, &linuxWorker{pid: uint32(pid), fd: fd, mode: args[2], t: t})
	}
	return refs
}
func assertServiceIsolation(t *testing.T, control, engine uint32) {
	t.Helper()
	c, err := os.ReadFile(fmt.Sprintf("/proc/%d/cgroup", control))
	if err != nil {
		t.Fatal(err)
	}
	e, err := os.ReadFile(fmt.Sprintf("/proc/%d/cgroup", engine))
	if err != nil {
		t.Fatal(err)
	}
	if string(c) == string(e) || !strings.Contains(string(c), "/netswitch.service") || !strings.Contains(string(e), "/netswitch-engine.service") {
		t.Fatal("services share a cgroup", string(c), string(e))
	}
}
