//go:build linux

package suite

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/AyoubAchour/net-switch/tests/linux/engine"
)

func httpsProbes(e *Env) {
	e.StartEngine(e.DefaultConfig())
	_, s := e.v1()
	for _, target := range []string{"1.1.1.1:443", "8.8.8.8:443", "9.9.9.9:443"} {
		// Full operator-specific validation: custom=false retains each response rule.
		r, err := s.Probe(e.Ctx(), "full-"+target, "a", engine.ProbeRequest{Target: target, Quick: false, Custom: false})
		e.T.Check(err == nil && r.OK && r.Kind == "full", "%s full HTTPS probe passes with the fixture CA (%+v, %v)", target, r, err)
	}
	for _, mode := range []string{"redirect", "portal", "wrong-certificate"} {
		if err := os.WriteFile(filepath.Join(e.Net.InetDir(), "probe-mode"), []byte(mode), 0644); err != nil {
			e.T.Fatalf("probe mode: %v", err)
		}
		r, err := s.Probe(e.Ctx(), "bad-"+mode, "a", engine.ProbeRequest{Target: "1.1.1.1:443", Quick: false, Custom: false})
		e.T.Check(err == nil && !r.OK && r.Error != "", "%s is refused (%+v, %v)", mode, r, err)
		if mode == "wrong-certificate" {
			e.T.Check(strings.Contains(r.Error, "certificate"), "certificate mismatch is reported plainly (%s)", r.Error)
		}
	}
}
