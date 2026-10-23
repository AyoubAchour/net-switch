package udp

import (
	"testing"

	"github.com/AyoubAchour/net-switch/internal/engine/platform"
	"github.com/AyoubAchour/net-switch/internal/engine/testfake"
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

func TestKnownSessionSurvivesWindowsIdentityReadFailure(t *testing.T) {
	for _, change := range []string{"identity", "generation", "missing"} {
		t.Run(change, func(t *testing.T) {
			n, _, sockets, _, ids, _ := setup(t, &testfake.Owners{Value: owner})
			send(n, dest, []byte("start"))
			socket := await(t, sockets)
			await(t, socket.out)
			ids.set(platform.Owner{Generation: owner.Generation, IdentityUnavailable: true})
			n.Reconcile(t.Context())
			if n.ReconcileIdentityFallbacks.Load() != 1 {
				t.Fatal("known generation fallback was not counted")
			}
			send(n, dest, []byte("still live"))
			if string(await(t, socket.out).b) != "still live" {
				t.Fatal("identity query failure cut the known flow")
			}
			next := owner
			switch change {
			case "identity":
				next.AppID = "different app"
			case "generation":
				next = platform.Owner{Generation: "replacement", IdentityUnavailable: true}
			case "missing":
				next = platform.Owner{}
			}
			ids.set(next)
			n.Reconcile(t.Context())
			await(t, socket.done)
			if n.ReconcileIdentityFallbacks.Load() != 1 {
				t.Fatal("changed identity was counted as a fallback")
			}
		})
	}
}
