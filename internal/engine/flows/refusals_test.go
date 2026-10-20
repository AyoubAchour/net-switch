package flows

import (
	"testing"

	"github.com/AyoubAchour/net-switch/internal/engine/platform"
)

func TestAdmissionRefusalsRecordTheOccupiedBudget(t *testing.T) {
	for _, test := range []struct {
		name, protocol, owner string
		limit                 func(*Limits)
		want                  Refusals
		begin                 bool
	}{
		{"total", "tcp", "known", func(l *Limits) { l.Flows = 2 }, Refusals{Total: 1}, true},
		{"UDP total", "udp", "known", func(l *Limits) { l.UDP = 2 }, Refusals{UDP: 1}, true},
		{"handshakes", "tcp", "known", func(l *Limits) { l.Handshakes = 2 }, Refusals{Handshakes: 1}, true},
		{"app", "tcp", "known", func(l *Limits) { l.PerApp = 2 }, Refusals{PerApp: 1}, false},
		{"UDP app", "udp", "known", func(l *Limits) { l.UDPPerApp = 2 }, Refusals{UDPPerApp: 1}, false},
		{"unknown TCP", "tcp", "", func(l *Limits) { l.Unknown = 2 }, Refusals{Unknown: 1}, false},
		{"unknown UDP", "udp", "", func(l *Limits) { l.UnknownUDP = 2 }, Refusals{UnknownUDP: 1}, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			limits := Defaults()
			test.limit(&limits)
			f := table(t, limits)
			// Both positions below the limit must accept a real reservation
			// and owner. Rejecting either is not a valid capacity refusal.
			for range 2 {
				x := admit(t, f, test.protocol, test.owner)
				defer x.Close()
			}
			if got := f.Stats(); got.Rejected != 0 {
				t.Fatalf("refused below the cap: %+v", got)
			}
			x, err := f.Begin(test.protocol, tuple)
			if !test.begin {
				if err != nil {
					t.Fatal(err)
				}
				_, err = x.Resolve(platform.Owner{AppID: test.owner})
				x.Close()
			}
			if err != ErrBudget {
				t.Fatalf("excess reservation: %v", err)
			}
			got := f.Stats()
			reasons := got.RefusedTCP
			if test.protocol == "udp" {
				reasons = got.RefusedUDP
			}
			if reasons != test.want || got.Rejected != 1 || got.RefusedTCP.Count()+got.RefusedUDP.Count() != got.Rejected {
				t.Fatalf("wrong classification: %+v", got)
			}
		})
	}
}

func TestRefusalBelowEveryBudgetCannotClaimUnknownOverflow(t *testing.T) {
	f := table(t, Defaults())
	// Exercise the diagnostic independently of the admission predicate:
	// an incorrect call below a cap must remain visibly unexplained.
	f.mu.Lock()
	f.refuseBegin("tcp")
	f.refuseOwner("tcp", "known")
	f.refuseOwner("udp", "")
	f.mu.Unlock()
	got := f.Stats()
	if got.RefusedTCP != (Refusals{Unexplained: 2}) || got.RefusedUDP != (Refusals{Unexplained: 1}) || got.Rejected != 3 {
		t.Fatalf("below-cap rejection was mislabeled: %+v", got)
	}
}
