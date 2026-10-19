//go:build linux

package suite

import (
	"os"
	"path/filepath"
	"strings"
)

func httpsProbes(e *Env) {
	e.StartEngine(e.DefaultConfig())
	_, s := e.v1()
	for _, operator := range []string{"cloudflare", "google", "quad9"} {
		r, err := s.Probe(e.Ctx(), "full-"+operator, "a", operator)
		e.T.Check(err == nil && r.OK, "%s full HTTPS probe passes with the fixture CA (%+v, %v)", operator, r, err)
	}
	for _, mode := range []string{"redirect", "portal", "wrong-certificate"} {
		if err := os.WriteFile(filepath.Join(e.Net.InetDir(), "probe-mode"), []byte(mode), 0644); err != nil {
			e.T.Fatalf("probe mode: %v", err)
		}
		r, err := s.Probe(e.Ctx(), "bad-"+mode, "a", "cloudflare")
		e.T.Check(err == nil && !r.OK && r.Error != "", "%s is refused (%+v, %v)", mode, r, err)
		if mode == "wrong-certificate" {
			e.T.Check(strings.Contains(r.Error, "certificate"), "certificate mismatch is reported plainly (%s)", r.Error)
		}
	}
}
