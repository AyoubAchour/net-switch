package lifecycle_test

import (
	"golang.org/x/sys/unix"
	"testing"
)

func suspendAdapter(t *testing.T, pid uint32) {
	t.Helper()
	if err := unix.Kill(int(pid), unix.SIGSTOP); err != nil {
		t.Fatal(err)
	}
}
