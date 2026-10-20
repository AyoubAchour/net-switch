package lifecycle_test

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

type linuxWorker struct {
	pid uint32
	fd  int
}

func (w *linuxWorker) id() uint32 { return w.pid }
func (w *linuxWorker) close()     { unix.Close(w.fd) }
func (w *linuxWorker) alive() bool {
	fds := []unix.PollFd{{Fd: int32(w.fd), Events: unix.POLLIN}}
	n, err := unix.Poll(fds, 0)
	return err == nil && n == 0
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
		fd, err := unix.PidfdOpen(int(pid), 0)
		if err != nil {
			continue
		}
		refs = append(refs, &linuxWorker{pid: uint32(pid), fd: fd})
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
