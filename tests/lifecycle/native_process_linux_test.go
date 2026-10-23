package lifecycle_test

import (
	"golang.org/x/sys/unix"
	"testing"
)

func pinNativeChild(t *testing.T, pid uint32) (func() bool, func() (uint32, bool), func()) {
	t.Helper()
	fd, err := unix.PidfdOpen(int(pid), 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { unix.Close(fd) })
	gone := func() bool {
		fds := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
		n, err := unix.Poll(fds, 0)
		if err != nil && err != unix.EINTR {
			t.Fatal(err)
		}
		return n > 0
	}
	if gone() {
		t.Fatal("native child was already dead before fault")
	}
	// A non-parent observer can pin/wait, but cannot reap the child's raw exit.
	return gone, func() (uint32, bool) { return 0, false }, func() {
		if err := unix.PidfdSendSignal(fd, unix.SIGCONT, nil, 0); err != nil && err != unix.ESRCH {
			t.Error("resume pinned native process", err)
		}
	}
}
