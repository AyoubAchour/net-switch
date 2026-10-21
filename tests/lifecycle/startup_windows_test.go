package lifecycle_test

import (
	"github.com/AyoubAchour/net-switch/internal/lifecycle"
	"path/filepath"
	"sync"
	"testing"
)

func blockDesktopActivation(t *testing.T, cfg lifecycle.Config) func() {
	broken := cfg
	broken.Mode = "invalid-test-mode"
	path := filepath.Join(cfg.Data, "service-config.json")
	if err := lifecycle.Save(path, broken); err != nil {
		t.Fatal(err)
	}
	var once sync.Once
	return func() {
		once.Do(func() {
			if err := lifecycle.Save(path, cfg); err != nil {
				t.Fatal(err)
			}
		})
	}
}
