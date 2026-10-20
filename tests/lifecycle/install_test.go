package lifecycle_test

import (
	"github.com/AyoubAchour/net-switch/internal/service"
	"os"
	"path/filepath"
	"testing"
)

func installationTrust(t *testing.T, dir string) {
	root := filepath.Join(dir, "trust-case")
	candidate := filepath.Join(root, "bin")
	if err := os.MkdirAll(candidate, 0755); err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(root)
	for _, name := range []string{"netswitch", "netswitch-engine", "netswitch-desktop", "netswitchctl", "adapter"} {
		if err := os.WriteFile(filepath.Join(candidate, binary(name)), []byte("non-executed trust fixture"), 0644); err != nil {
			t.Fatal(err)
		}
	}
	adapter := filepath.Join(candidate, binary("adapter"))
	if err := service.CheckInstallation(candidate, adapter); err != nil {
		t.Fatal("trusted installation precondition", err)
	}
	for _, path := range []string{filepath.Join(candidate, binary("netswitch")), adapter, root} {
		restore := writableInstallPath(t, path)
		err := service.CheckInstallation(candidate, adapter)
		restore()
		if err == nil {
			t.Fatal("non-admin writable executable or ancestor was accepted", path)
		}
	}
	if err := service.CheckInstallation(candidate, adapter); err != nil {
		t.Fatal("legitimate installation rejected after controls", err)
	}
}
