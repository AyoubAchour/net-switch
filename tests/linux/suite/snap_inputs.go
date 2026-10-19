//go:build linux

package suite

import (
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/AyoubAchour/net-switch/tests/linux/harness"
)

// Also read by the Actions cache/download steps; one source for every pin.
//
//go:embed snap-inputs.json
var snapPins []byte

type fixtureHost func(time.Duration, int, string, ...string) (string, error)

func installSnapInputs(ctx context.Context, host fixtureHost, logf func(string, ...any)) (string, error) {
	var pins map[string]map[string]struct {
		Revision string `json:"revision"`
		SHA256   string `json:"sha256"`
	}
	if err := json.Unmarshal(snapPins, &pins); err != nil {
		return "", err
	}
	cache := os.Getenv("NSACCEPT_SNAP_CACHE")
	if cache == "" {
		return "", fmt.Errorf("NSACCEPT_SNAP_CACHE is required: run tests/linux/snap-inputs.sh fetch <directory> first; snap provisioning never downloads from the store")
	}
	if _, err := host(time.Minute, 1, "snap", "set", "system", "store.access=offline"); err != nil {
		return "", fmt.Errorf("disabling Snap Store access: %w", err)
	}
	if err := checkSnapOffline(ctx, host, logf); err != nil {
		return "", err
	}
	var recorded []string
	// Even the empty Actions images need no store access: install snapd itself
	// first, then the base, before the app's prerequisite resolver can run.
	for _, name := range []string{"snapd", snapBase} {
		pin, ok := pins[runtime.GOARCH][name]
		if !ok || pin.Revision == "" || len(pin.SHA256) != 64 {
			return "", fmt.Errorf("no %s revision and SHA-256 pinned for %s", name, runtime.GOARCH)
		}
		base := filepath.Join(cache, name+"_"+pin.Revision)
		sum, err := harness.FileSHA256(base + ".snap")
		if err != nil {
			return "", fmt.Errorf("reading cached %s revision %s: %w", name, pin.Revision, err)
		}
		if sum != pin.SHA256 {
			return "", fmt.Errorf("%s revision %s SHA-256 mismatch: got %s, want %s", name, pin.Revision, sum, pin.SHA256)
		}
		record := fmt.Sprintf("%s %s revision %s SHA-256 %s", name, runtime.GOARCH, pin.Revision, sum)
		logf("%s (verified)", record)
		if _, err := host(time.Minute, 1, "snap", "ack", base+".assert"); err != nil {
			return "", fmt.Errorf("acknowledging cached %s assertion: %w", name, err)
		}
		// A local install also replaces an already-installed revision. Check
		// current so newer runner images cannot silently change the fixture.
		current := filepath.Join("/snap", name, "current")
		rev, err := os.Readlink(current)
		if err != nil && !os.IsNotExist(err) {
			return "", err
		}
		if rev != pin.Revision {
			if _, err := host(3*time.Minute, 1, "snap", "install", base+".snap"); err != nil {
				return "", fmt.Errorf("installing cached %s revision %s offline (store access is forbidden): %w", name, pin.Revision, err)
			}
		}
		rev, err = os.Readlink(current)
		if err != nil || rev != pin.Revision {
			return "", fmt.Errorf("%s current revision is %q, want %s: %v", name, rev, pin.Revision, err)
		}
		recorded = append(recorded, record+" (verified, installed offline)")
	}
	// Installing snapd can restart the daemon. Recheck before the test snap.
	if err := checkSnapOffline(ctx, host, logf); err != nil {
		return "", err
	}
	return strings.Join(recorded, "; "), nil
}

func checkSnapOffline(ctx context.Context, host fixtureHost, logf func(string, ...any)) error {
	access, err := host(time.Minute, 1, "snap", "get", "system", "store.access")
	if err != nil || strings.TrimSpace(access) != "offline" {
		return fmt.Errorf("Snap Store access is not offline: %q (%v)", access, err)
	}
	// Check the daemon's behavior, not just the stored setting. A missing
	// prerequisite must fail immediately, before a store connection is made.
	c, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	out, probeErr := exec.CommandContext(c, "snap", "debug", "connectivity").CombinedOutput()
	if probeErr == nil || !strings.Contains(string(out), "store is marked offline") {
		return fmt.Errorf("Snap Store offline guard failed: connectivity probe: %v: %s", probeErr, strings.TrimSpace(string(out)))
	}
	logf("Snap Store offline guard: connectivity probe rejected (store is marked offline)")
	return nil
}
