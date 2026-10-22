//go:build windows && wintun_integrity

package wintun

import "testing"

func attachIntegrityRings(t *testing.T, d *integrityDiagnostic) func() {
	t.Helper()
	h := &integrityRingObserver{observe: d.native}
	if !integrityRingHook.CompareAndSwap(nil, h) {
		t.Fatal("integrity observer already installed; fixtures must be serial")
	}
	return func() { integrityRingHook.CompareAndSwap(h, nil) }
}
