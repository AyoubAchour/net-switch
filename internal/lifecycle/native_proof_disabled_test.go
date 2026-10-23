//go:build !lifecycle_test

package lifecycle

import (
	"testing"

	"github.com/AyoubAchour/net-switch/internal/engine/host"
)

func TestProductNativeHostHasNoFaultInterposer(t *testing.T) {
	var options host.Options
	configureNativeProof(t.TempDir(), &options)
	if options.WrapTun != nil || options.Configure != nil || options.ProbeTLS != nil || options.ProbeError != nil || options.RetirementError != nil {
		t.Fatal("product builds must not interpose forwarding faults")
	}
}
