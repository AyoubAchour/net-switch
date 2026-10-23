package lifecycle_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/AyoubAchour/net-switch/tests/linux/inet"
)

func linuxNativeProbe(t *testing.T, data, inetDir string) nativeProbeFixture {
	t.Helper()
	ca, err := os.ReadFile(filepath.Join(inetDir, "probe-ca.pem"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(data, "probe-test-ca.pem"), ca, 0600); err != nil {
		t.Fatal(err)
	}
	wrong := func(t *testing.T, bad bool) {
		mode := "redirect"
		if bad {
			mode = "wrong-certificate"
		}
		if err := os.WriteFile(filepath.Join(inetDir, "probe-mode"), []byte(mode), 0600); err != nil {
			t.Fatal(err)
		}
	}
	wrong(t, false)
	return nativeProbeFixture{target: "1.1.1.1:443", wrong: wrong, seen: func(t *testing.T) (int, string) {
		records, err := inet.ReadRecords(filepath.Join(inetDir, inet.EventsFile))
		if err != nil {
			t.Fatal(err)
		}
		count, last := 0, ""
		for _, r := range records {
			if r.Kind == "probe-http" {
				count++
				last = r.Data
			}
		}
		return count, last
	}}
}
