//go:build linux

package linux

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

func TestKernelFlatpakBindMountSafety(t *testing.T) {
	requireKernelNamespace(t)
	if os.Getenv("NETSWITCH_METADATA_MOUNT_HELPER") != "1" {
		self, err := os.Executable()
		if err != nil {
			t.Fatal(err)
		}
		cmd := exec.Command("unshare", "--mount", "--propagation", "private", "--", self, "-test.run=^TestKernelFlatpakBindMountSafety$", "-test.v")
		cmd.Env = append(os.Environ(), "NETSWITCH_METADATA_MOUNT_HELPER=1")
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("private mount namespace: %v\n%s", err, out)
		}
		t.Log(string(out))
		return
	}
	root := t.TempDir()
	path := filepath.Join(root, ".flatpak-info")
	if err := os.WriteFile(path, nil, 0600); err != nil {
		t.Fatal(err)
	}
	if err := unix.Mount("/dev/null", path, "", unix.MS_BIND, ""); err != nil {
		t.Fatal(err)
	}
	defer unix.Unmount(path, unix.MNT_DETACH)
	st, err := os.Stat(path)
	if err != nil || st.Mode()&os.ModeDevice == 0 {
		t.Fatal("special-file bind fixture is not a device")
	}
	if _, err := readFlatpakInfo("/proc/self/root"+root, make([]byte, 64<<10)); !errors.Is(err, errNotRegular) {
		t.Fatalf("bound device was not rejected: %v", err)
	}
	if err := unix.Unmount(path, 0); err != nil {
		t.Fatal(err)
	}
	metadata := filepath.Join(t.TempDir(), "metadata")
	want := "[Application]\nname=org.example.BindMounted\n"
	if err := os.WriteFile(metadata, []byte(want), 0600); err != nil {
		t.Fatal(err)
	}
	if err := unix.Mount(metadata, path, "", unix.MS_BIND, ""); err != nil {
		t.Fatal(err)
	}
	if err := unix.Mount("", path, "", unix.MS_BIND|unix.MS_REMOUNT|unix.MS_RDONLY, ""); err != nil {
		t.Fatal(err)
	}
	got, err := readFlatpakInfo("/proc/self/root"+root, make([]byte, 64<<10))
	if err != nil || string(got) != want {
		t.Fatalf("legitimate Flatpak bind mount failed: %q %v", got, err)
	}
}
