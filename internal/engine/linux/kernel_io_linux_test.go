//go:build linux

package linux

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

func TestKernelMetadataFastPathsStayOutsideProcessRoots(t *testing.T) {
	for _, path := range []string{"/proc/1/root/stat", "/proc/self/root/.flatpak-info", "/proc/1/fd/3", "/proc/../stat", "/proc/1/../2/stat", "/sys/fs/cgroup/../other/cgroup.procs", "/sys/fs/cgroup/./cgroup.procs", "/sys/fs/cgroup-other/cgroup.procs"} {
		if kernelLookupPath(path) {
			t.Fatalf("process-controlled or noncanonical path entered direct kernel I/O: %s", path)
		}
	}
	for _, path := range []string{"/proc/self/stat", "/proc/self/environ", "/proc/self/fd", "/sys/fs/cgroup/cgroup.procs", "/sys/fs/cgroup/apps/example/cgroup.procs"} {
		if !kernelLookupPath(path) {
			t.Fatalf("fixed kernel path was not recognized: %s", path)
		}
	}
	fd, direct, err := openKernelFile("/proc/self/stat", unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NONBLOCK|unix.O_NOFOLLOW)
	if err != nil {
		t.Fatal(err)
	}
	defer closeKernelFile(fd, direct)
	if !direct {
		t.Fatal("real proc metadata did not use the kernel path")
	}
	if err := regularKernelFile(fd, 4096, direct); err != nil {
		t.Fatal(err)
	}
	data, err := readBoundedWith(fd, make([]byte, 4096), readKernelData)
	if err != nil {
		t.Fatal(err)
	}
	start, err := parseProcessStart(data)
	if err != nil || start == 0 {
		t.Fatalf("direct stat read: %d %v", start, err)
	}
	oracle, err := os.ReadFile("/proc/self/stat")
	if err != nil {
		t.Fatal(err)
	}
	want, err := parseProcessStart(oracle)
	if err != nil || start != want {
		t.Fatalf("kernel incarnation changed through direct I/O: %d/%d %v", start, want, err)
	}
	exe, err := readProcLink("/proc/self/exe")
	if err != nil {
		t.Fatal(err)
	}
	wantExe, err := os.Readlink("/proc/self/exe")
	if err != nil || exe != wantExe {
		t.Fatalf("direct executable link changed: %q/%q %v", exe, wantExe, err)
	}

	// A regular fixture outside the fixed kernel trees keeps ordinary I/O;
	// size and no-follow checks remain identical on both paths.
	path := filepath.Join(t.TempDir(), "stat")
	if err := os.WriteFile(path, []byte("fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	fd2, direct2, err := openKernelFile(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NONBLOCK|unix.O_NOFOLLOW)
	if err != nil {
		t.Fatal(err)
	}
	defer closeKernelFile(fd2, direct2)
	if direct2 {
		t.Fatal("regular filesystem entered direct kernel I/O")
	}
	got, err := readInto(path, make([]byte, 64))
	if err != nil || !bytes.Equal(got, []byte("fixture")) {
		t.Fatalf("ordinary bounded path changed: %q %v", got, err)
	}
}
