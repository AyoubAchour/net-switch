package flows

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/AyoubAchour/net-switch/internal/engine/flowapi"
	"github.com/AyoubAchour/net-switch/internal/engine/platform"
	"github.com/AyoubAchour/net-switch/internal/engine/policy"
)

func revision(n uint64) policy.Revision {
	c := policy.Config{Lines: []platform.Line{{ID: "A"}, {ID: "B"}}, Lanes: map[string]string{"A": "A", "B": "B"}, AppLines: map[string]string{"pinned": "B"}, Combine: true, Shares: map[string]uint64{"A": 1, "B": 1}, IPv6: true}
	return policy.Revision{N: n, Hash: policy.Hash(c), Config: c}
}

var tuple = platform.Tuple{Source: netip.MustParseAddrPort("198.18.0.2:40000"), Destination: netip.MustParseAddrPort("203.0.113.7:443")}

func table(t *testing.T, l Limits) *Table {
	t.Helper()
	f := New(l, nil)
	if _, err := f.Apply(revision(1)); err != nil {
		t.Fatal(err)
	}
	return f
}
func admit(t *testing.T, f *Table, proto, app string) flowapi.Ticket {
	t.Helper()
	x, err := f.Begin(proto, tuple)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := x.Resolve(platform.Owner{AppID: app}); err != nil {
		t.Fatal(err)
	}
	return x
}

func TestRevisionsLanesAndClosedTotals(t *testing.T) {
	f := table(t, Defaults())
	x := admit(t, f, "tcp", "pinned")
	x.Add(10, 20)
	r := revision(2)
	r.Config.Lanes["B"] = "A"
	r.Hash = policy.Hash(r.Config)
	a, err := f.Apply(r)
	if err != nil {
		t.Fatal(err)
	}
	y := admit(t, f, "tcp", "pinned")
	p, err := f.Page("")
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Flows) != 2 || p.Flows[0].Line != "B" || p.Flows[1].Line != "A" || p.Flows[0].Revision != 1 || p.Flows[1].Revision != 2 {
		t.Fatal("open flow moved", p)
	}
	x.SetCancel(func() { x.Close() })
	y.SetCancel(func() { y.Close() })
	result, err := f.CloseFlows(Selector{App: "pinned", NotLine: "A"}, a.Point)
	if err != nil || result.Closed != 1 {
		t.Fatal(result, err)
	}
	if f.Totals().Apps["pinned"] != (Bytes{10, 20}) {
		t.Fatal("closed bytes lost")
	}
	if f.Stats().Flows != 1 {
		t.Fatal("new flow closed")
	}
	y.Close()
	if f.Stats().TCPBytes != 0 || f.Stats().Handshakes != 0 {
		t.Fatal("reservation leaked")
	}
	if _, err := f.Apply(revision(1)); err != ErrStale {
		t.Fatal(err)
	}
	same, err := f.Apply(r)
	if err != nil || same != a {
		t.Fatal("idempotent apply changed point")
	}
	r.Config.Combine = false
	r.Hash = policy.Hash(r.Config)
	if _, err := f.Apply(r); err != ErrConflict {
		t.Fatal(err)
	}
}
func TestRejectedAndPredictDoNotAdvance(t *testing.T) {
	f := table(t, Defaults())
	r := revision(2)
	r.Config.Blocked = []string{"B"}
	delete(r.Config.Shares, "B")
	r.Hash = policy.Hash(r.Config)
	f.Apply(r)
	x, _ := f.Begin("tcp", tuple)
	if _, err := x.Resolve(platform.Owner{AppID: "pinned"}); err == nil {
		t.Fatal("blocked admitted")
	}
	x.Close()
	for range 100 {
		f.Predict("unknown")
	}
	if f.k.Load() != 0 {
		t.Fatal("rejection/predict advanced sequence")
	}
	y := admit(t, f, "udp", "")
	defer y.Close()
	if f.k.Load() != 1 {
		t.Fatal("admission did not advance once")
	}
	y.Resolve(platform.Owner{})
	if f.k.Load() != 1 {
		t.Fatal("repeat advanced")
	}
}

func TestEveryAdmissionLimit(t *testing.T) {
	for _, name := range []string{"flows", "handshakes", "udp", "perApp", "udpPerApp", "unknown", "unknownUDP"} {
		t.Run(name, func(t *testing.T) {
			l := Defaults()
			proto, app := "tcp", "known"
			switch name {
			case "flows":
				l.Flows = 1
			case "handshakes":
				l.Handshakes = 1
			case "udp":
				l.UDP = 1
				proto = "udp"
			case "perApp":
				l.PerApp = 1
			case "udpPerApp":
				l.UDPPerApp = 1
				proto = "udp"
			case "unknown":
				l.Unknown = 1
				app = ""
			case "unknownUDP":
				l.UnknownUDP = 1
				proto = "udp"
				app = ""
			}
			f := table(t, l)
			x := admit(t, f, proto, app)
			defer x.Close()
			y, err := f.Begin(proto, tuple)
			if err == nil {
				_, err = y.Resolve(platform.Owner{AppID: app})
				y.Close()
			}
			if err != ErrBudget {
				t.Fatalf("%s overflow accepted: %v", name, err)
			}
		})
	}
}
func TestPendingAndSnapshotBudgets(t *testing.T) {
	l := Defaults()
	l.PendingBytes = 10
	l.SnapshotBytes = 1
	f := table(t, l)
	if !f.ReservePending(10) || f.ReservePending(1) {
		t.Fatal("pending byte cap")
	}
	f.ReleasePending(10)
	x := admit(t, f, "udp", "known")
	defer x.Close()
	if _, err := f.Page(""); err != ErrBudget {
		t.Fatal("snapshot byte cap")
	}
}
func TestSnapshotPaginationExpiryAndLimits(t *testing.T) {
	l := Defaults()
	f := table(t, l)
	var tickets []flowapi.Ticket
	for range 130 {
		tickets = append(tickets, admit(t, f, "udp", "known"))
	}
	defer func() {
		for _, x := range tickets {
			x.Close()
		}
	}()
	var first Page
	for range 4 {
		p, err := f.Page("")
		if err != nil {
			t.Fatal(err)
		}
		first = p
	}
	if _, err := f.Page(""); err != ErrBudget {
		t.Fatal("snapshot count limit")
	}
	seen := len(first.Flows)
	cursor := first.Cursor
	for cursor != "" {
		p, err := f.Page(cursor)
		if err != nil {
			t.Fatal(err)
		}
		seen += len(p.Flows)
		cursor = p.Cursor
	}
	if seen != 130 {
		t.Fatal("pagination lost entries")
	}
	f.now = func() time.Time { return time.Now().Add(11 * time.Second) }
	if _, err := f.Page(first.Cursor); err == nil {
		t.Fatal("expired cursor accepted")
	}
	if f.Stats().SnapshotBytes != 0 {
		t.Fatal("snapshot bytes leaked")
	}
}
func TestTwentyThousandUDPSessions(t *testing.T) {
	f := table(t, Defaults())
	var tickets []flowapi.Ticket
	for range 20000 {
		x, err := f.Begin("udp", tuple)
		if err == nil {
			tickets = append(tickets, x)
		} else if err != ErrBudget {
			t.Fatal(err)
		}
	}
	if len(tickets) != 16384 {
		t.Fatal(len(tickets))
	}
	for _, x := range tickets {
		x.Close()
	}
}
func TestRejectionNoticeLimits(t *testing.T) {
	f := table(t, Defaults())
	fixed := time.Now()
	f.now = func() time.Time { return fixed }
	for range 1000 {
		if !f.AllowReject("a") {
			t.Fatal("early app limit")
		}
	}
	if f.AllowReject("a") {
		t.Fatal("app limit")
	}
	for _, app := range []string{"b", "c", "d", "e"} {
		for range 1000 {
			if !f.AllowReject(app) {
				t.Fatal("early global limit")
			}
		}
	}
	if f.AllowReject("f") {
		t.Fatal("global limit")
	}
}

type failStore struct{}

func (failStore) SaveApplied(policy.Applied) error { return errors.New("fsync failed") }
func TestPersistenceFailureNotApplied(t *testing.T) {
	f := New(Defaults(), failStore{})
	if _, err := f.Apply(revision(1)); err == nil || f.Applied() != nil {
		t.Fatal("failed save applied")
	}
}
func TestCancellationBeforeRegistration(t *testing.T) {
	f := table(t, Defaults())
	x := admit(t, f, "tcp", "known")
	f.CloseAll()
	ctx, cancel := context.WithCancel(context.Background())
	x.SetCancel(cancel)
	if ctx.Err() == nil {
		t.Fatal("late cancel registration lost")
	}
	x.Close()
}

func TestSharedReconnectKeepsRoutedFlows(t *testing.T) {
	f := table(t, Defaults())
	x := admit(t, f, "tcp", "shared")
	defer x.Close()
	if _, err := f.CloseFlows(Selector{App: "shared", NotLine: "A"}, 0); err == nil {
		t.Fatal("shared routed flows were reconnectable")
	}
	if f.Stats().Flows != 1 {
		t.Fatal("shared flow closed")
	}
}
