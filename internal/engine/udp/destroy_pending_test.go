package udp

import (
	"net/netip"
	"testing"
	"time"

	"github.com/AyoubAchour/net-switch/internal/engine/testfake"
)

func TestDestroyDuringPendingLookup(t *testing.T) {
	for _, wildcard := range []bool{false, true} {
		for _, matching := range []bool{false, true} {
			t.Run(stringName(wildcard, matching), func(t *testing.T) {
				gate := make(chan struct{})
				n, _, sockets, _, _, calls := setup(t, &testfake.Owners{Value: owner, Gate: gate})
				send(n, dest, []byte("pending"))
				b := n.bucket(local)
				b.Lock()
				s := b.m[local]
				b.Unlock()
				s.mu.Lock()
				pending := s.owner.Generation == "" && !s.active
				s.mu.Unlock()
				if !pending {
					t.Fatal("fixture lookup was not pending")
				}
				source := local
				if wildcard {
					source = netip.AddrPortFrom(netip.IPv4Unspecified(), local.Port())
				}
				generation := "old-generation"
				if matching {
					generation = owner.Generation
				}
				n.Destroy(source, generation)
				close(gate)
				if matching {
					select {
					case <-s.done:
					case <-time.After(time.Second):
						t.Fatal("pending destroy was lost")
					}
					if calls.Load() != 0 {
						t.Fatal("destroyed generation dialed")
					}
				} else {
					sock := await(t, sockets)
					if string(await(t, sock.out).b) != "pending" {
						t.Fatal("stale destroy changed payload")
					}
				}
			})
		}
	}
}

func stringName(wildcard, matching bool) string {
	name := "exact"
	if wildcard {
		name = "wildcard"
	}
	if matching {
		return name + "-matching"
	}
	return name + "-stale"
}
