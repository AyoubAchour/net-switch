package flows

import (
	"testing"
	"time"
)

func TestTimeWaitReleasesAdmissionAndHidesFlows(t *testing.T) {
	for _, app := range []string{"pinned", ""} {
		t.Run(app, func(t *testing.T) {
			l := Defaults()
			l.Flows, l.PerApp, l.Unknown, l.TimeWait = 1, 1, 1, 1
			f := table(t, l)
			x := admit(t, f, "tcp", app).(*ticket)
			id := x.record.ID
			x.Add(10, 20)
			if !x.TimeWait() || !x.TimeWait() {
				t.Fatal("first endpoint did not retain TIME_WAIT")
			}
			if g := f.Stats(); g.Flows != 0 || g.Handshakes != 0 || g.Unknown != 0 || g.TimeWait != 1 {
				t.Fatal("TIME_WAIT kept admission", g)
			}
			if page, err := f.Page(""); err != nil || len(page.Flows) != 0 {
				t.Fatal("TIME_WAIT appeared live", page, err)
			}
			for _, selector := range []Selector{{Line: x.record.Line}, {IDs: []uint64{id}}} {
				if result, err := f.CloseFlows(selector, 0); err != nil || result.Closed != 0 {
					t.Fatal("close-by-line/id closed TIME_WAIT", result, err)
				}
			}
			y := admit(t, f, "tcp", app).(*ticket)
			if y.TimeWait() || y.TimeWait() {
				t.Fatal("full TIME_WAIT pool did not skip")
			}
			if g := f.Stats(); g.Flows != 0 || g.TimeWait != 1 || g.TimeWaitSkipped != 1 || g.Rejected != 0 {
				t.Fatal(g)
			}
			x.Add(2, 3) // Relay completion may trail the TCP FIN processing.
			x.EndTimeWait()
			x.EndTimeWait()
			z := admit(t, f, "tcp", app).(*ticket)
			if !z.TimeWait() {
				t.Fatal("removed endpoint did not return its slot")
			}
			for _, ticket := range []*ticket{x, y, z} {
				ticket.Close()
				ticket.Close()
			}
			if g := f.Stats(); g.Flows != 0 || g.Handshakes != 0 || g.TimeWait != 0 || g.TCPBytes != 0 {
				t.Fatal("reservations leaked or released twice", g)
			}
			if got := f.Totals().Apps[app]; got != (Bytes{12, 23}) {
				t.Fatal("final accounting lost or doubled", got)
			}
		})
	}
}

func TestTimeWaitSkipLogsAreRateLimited(t *testing.T) {
	l := Defaults()
	l.TimeWait = 0
	f := table(t, l)
	now := time.Unix(100, 0)
	f.now = func() time.Time { return now }
	for range 1000 {
		x := admit(t, f, "tcp", "pinned").(*ticket)
		if x.TimeWait() {
			t.Fatal("retained endpoint with zero cap")
		}
		x.Close()
	}
	if len(f.events) != 1 || f.Stats().TimeWaitSkipped != 1000 {
		t.Fatal("skip count or log rate wrong", len(f.events), f.Stats())
	}
	now = now.Add(time.Second)
	x := admit(t, f, "tcp", "pinned").(*ticket)
	x.TimeWait()
	x.Close()
	if len(f.events) != 2 {
		t.Fatal("next second did not log")
	}
}
