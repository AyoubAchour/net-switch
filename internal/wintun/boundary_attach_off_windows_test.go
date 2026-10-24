//go:build windows && !wintun_boundaries

package wintun

import "testing"

func attachWordBoundaries(t *testing.T, _ *fixture) (wordBoundaryCapture, func()) {
	t.Fatal("word boundary checks require -tags=wintun_boundaries")
	return nil, nil
}
func observeWordDLL(_ string, _ []byte) {}
