//go:build linux

package linux

import (
	"os"
	"os/exec"
	"runtime"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestProcOpenAcrossDescriptorTableBoundary(t *testing.T) {
	if os.Getenv("NETSWITCH_FD_BOUNDARY_CHILD") != "1" {
		ctx := t.Context()
		cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestProcOpenAcrossDescriptorTableBoundary$", "-test.v")
		cmd.Env = append(os.Environ(), "NETSWITCH_FD_BOUNDARY_CHILD=1")
		output, err := cmd.CombinedOutput()
		t.Log(string(output))
		if err != nil {
			t.Fatal(err)
		}
		return
	}
	runtime.GOMAXPROCS(2)
	before, err := descriptorTableSize()
	if err != nil || before != 64 {
		t.Fatalf("fresh-process FD table precondition: %d %v", before, err)
	}
	seed, err := unix.Open("/dev/null", unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(seed)
	var held []int
	defer func() {
		for _, fd := range held {
			unix.Close(fd)
		}
	}()
	for {
		fd, err := unix.FcntlInt(uintptr(seed), unix.F_DUPFD_CLOEXEC, 0)
		if err != nil {
			t.Fatal(err)
		}
		held = append(held, fd)
		if fd == before-1 {
			break
		}
		if fd >= before {
			t.Fatal("fixture crossed boundary before measured open")
		}
	}
	began := time.Now()
	cold, err := openProcDescriptors("/proc/self/fd")
	coldTime := time.Since(began)
	if err != nil {
		t.Fatal(err)
	}
	fd := cold.fd
	if fd != before {
		t.Fatalf("measured open did not cross the proven boundary: fd=%d size=%d", fd, before)
	}
	cold.Close()
	after, err := descriptorTableSize()
	if err != nil || after <= before {
		t.Fatalf("kernel table did not expand: %d -> %d (%v)", before, after, err)
	}
	began = time.Now()
	warm, err := openProcDescriptors("/proc/self/fd")
	warmTime := time.Since(began)
	if err != nil {
		t.Fatal(err)
	}
	if warm.fd != fd {
		t.Fatal("warm comparison did not reuse the same descriptor")
	}
	warm.Close()
	t.Logf("FD table %d -> %d; cold proc open fd=%d duration=%s exceeds-8ms=%t; same-fd warm open=%s", before, after, fd, coldTime, coldTime > 8*time.Millisecond, warmTime)
}
