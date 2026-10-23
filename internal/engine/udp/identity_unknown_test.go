package udp

import (
	"testing"

	"github.com/AyoubAchour/net-switch/internal/engine/platform"
)

func TestUnknownGenerationValidationKeepsKnownIdentityChecks(t *testing.T) {
	unknown := platform.Owner{Generation: owner.Generation}
	if !same(unknown, owner) || same(owner, unknown) {
		t.Fatal("unknown admission may gain evidence; known admission may not lose it")
	}
	for _, changed := range []platform.Owner{
		{Generation: "replacement"}, {},
	} {
		if same(unknown, changed) {
			t.Fatal("unknown admission ignored a changed or missing native generation")
		}
	}
	changed := owner
	changed.StartTime++
	if same(owner, changed) {
		t.Fatal("known identity lost its process-restart check")
	}
}
