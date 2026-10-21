//go:build linux

package linux

import (
	"errors"
	"os"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func TestKernelPingGroupRangeDiagnostic(t *testing.T) {
	requireKernelNamespace(t)
	const path = "/proc/sys/net/ipv4/ping_group_range"
	old, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	defer os.WriteFile(path, old, 0600)
	if err := os.WriteFile(path, []byte("1 0"), 0600); err != nil {
		t.Fatal(err)
	}
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, unix.IPPROTO_ICMP)
	if err == nil {
		unix.Close(fd)
		t.Fatal("disabled ping range did not reproduce kernel refusal")
	}
	if !errors.Is(err, unix.EACCES) {
		t.Fatalf("unexpected ping socket error: %v", err)
	}
	if err := pingPermission(); err == nil || !strings.Contains(err.Error(), "ping_group_range") || !strings.Contains(err.Error(), "gid 0") {
		t.Fatalf("refusal has no actionable diagnosis: %v", err)
	}
	if err := os.WriteFile(path, []byte("0 0"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := pingPermission(); err != nil {
		t.Fatalf("permitted root group reported unavailable: %v", err)
	}
	fd, err = unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, unix.IPPROTO_ICMP)
	if err != nil {
		t.Fatalf("permitted root ping socket: %v", err)
	}
	unix.Close(fd)
}
