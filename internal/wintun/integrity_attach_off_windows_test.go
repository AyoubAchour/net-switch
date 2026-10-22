//go:build windows && !wintun_integrity

package wintun

import "testing"

func attachIntegrityRings(t *testing.T, _ *integrityDiagnostic) func() {
	t.Fatal("integrity diagnostic requires -tags=wintun_integrity")
	return nil
}
