//go:build windows

package winengine

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"testing"
	"time"

	"github.com/AyoubAchour/net-switch/internal/engine/platform"
	"golang.org/x/sys/windows"
)

// SYSTEM-DESIGN 5.9: a refused automatic port choice gets at most four fresh
// attempts within 10 ms, each counted, for the UDP bind and the TCP dial
// alike (TCP: 2026-10-22, a design decision recorded in the spec). The
// refusals are injected; the OS is not asked.
func TestPortRetriesAreBoundedAndCounted(t *testing.T) {
	udpRefused := os.NewSyscallError("bind", windows.WSAENOBUFS)
	tcpBindRefused := os.NewSyscallError("bind", windows.WSAENOBUFS)
	tcpConnectRefused := os.NewSyscallError("connectex", windows.WSAEADDRINUSE)
	denied := os.NewSyscallError("bind", windows.WSAEACCES)
	peerRefused := os.NewSyscallError("connectex", windows.WSAECONNREFUSED)
	cancelled := context.Canceled
	// script returns the given errors in order, then success.
	script := func(calls *int, errs ...error) func() (*udpSocket, error) {
		return func() (*udpSocket, error) {
			*calls++
			if *calls <= len(errs) {
				return nil, errs[*calls-1]
			}
			return &udpSocket{}, nil
		}
	}
	for _, protocol := range []struct {
		name      string
		retryable func(error) bool
		refused   []error
	}{
		{"udp", udpPortRefusal, []error{udpRefused}},
		{"tcp", portLimit, []error{tcpBindRefused, tcpConnectRefused}},
	} {
		for _, refused := range protocol.refused {
			for _, tc := range []struct {
				name                       string
				errs                       []error
				calls                      int
				first, fresh, final, other uint64
				recovered                  []uint64
				wantErr                    error
			}{
				{"first attempt", nil, 1, 0, 0, 0, 0, []uint64{0, 0, 0, 0}, nil},
				{"other error is not retried", []error{denied}, 1, 0, 0, 0, 0, []uint64{0, 0, 0, 0}, windows.WSAEACCES},
				{"second fresh attempt", []error{refused, refused}, 3, 1, 2, 0, 0, []uint64{0, 1, 0, 0}, nil},
				{"every attempt refused", []error{refused, refused, refused, refused, refused, refused}, 5, 1, 4, 1, 0, []uint64{0, 0, 0, 0}, refused},
				// Review of 822789db: a fresh attempt that gets a port and then
				// fails otherwise is not a final refusal; the gate never sees it.
				{"other error after a refusal ends it", []error{refused, denied}, 2, 1, 1, 0, 1, []uint64{0, 0, 0, 0}, windows.WSAEACCES},
				{"connection refused after a refusal", []error{refused, refused, peerRefused}, 3, 1, 2, 0, 1, []uint64{0, 0, 0, 0}, windows.WSAECONNREFUSED},
				{"cancelled after a refusal", []error{refused, cancelled}, 2, 1, 1, 0, 1, []uint64{0, 0, 0, 0}, context.Canceled},
			} {
				t.Run(protocol.name+"/"+refused.Error()+"/"+tc.name, func(t *testing.T) {
					var r portRetries
					calls := 0
					s, outcome, err := retryOpen(&r, protocol.retryable, script(&calls, tc.errs...))
					if tc.wantErr == nil && (err != nil || s == nil) || tc.wantErr != nil && (!errors.Is(err, tc.wantErr) || s != nil) {
						t.Fatalf("open = %v, %v; want error %v", s, err, tc.wantErr)
					}
					stats := r.stats()
					if calls != tc.calls || outcome.Attempts != calls || outcome.Refused != (tc.final == 1) || stats["firstRefusals"] != tc.first ||
						stats["freshAttempts"] != tc.fresh || stats["finalFailures"] != tc.final || stats["otherFailures"] != tc.other {
						t.Fatalf("calls %d outcome %+v stats %v", calls, outcome, stats)
					}
					for i, want := range tc.recovered {
						if got := stats["recoveredOnFreshAttempt"].([]uint64)[i]; got != want {
							t.Fatalf("recovered on fresh attempt %d = %d, want %d", i+1, got, want)
						}
					}
				})
			}
		}
	}
	t.Run("udp does not retry a connect address conflict", func(t *testing.T) {
		var r portRetries
		calls := 0
		_, _, err := retryOpen(&r, udpPortRefusal, script(&calls, tcpConnectRefused))
		if calls != 1 || !errors.Is(err, windows.WSAEADDRINUSE) || r.firstRefusals.Load() != 0 {
			t.Fatalf("calls %d err %v", calls, err)
		}
	})
	// The window is read on an injected clock: a fresh attempt that ends
	// 10 ms or more after the first refusal is the last one, however coarse
	// Go's own clock is; one ending 1 ns sooner is not.
	for _, tc := range []struct {
		name    string
		elapsed time.Duration
		calls   int
		ended   uint64
	}{
		{"window passed", freshWindow, 2, 1},
		{"window passed by more than a tick", freshWindow + 15625*time.Microsecond, 2, 1},
		{"window not yet passed", freshWindow - time.Nanosecond, 1 + freshAttempts, 0},
	} {
		t.Run("time window/"+tc.name, func(t *testing.T) {
			clock := 5 * time.Second
			r := portRetries{now: func() time.Duration { return clock }}
			calls := 0
			_, outcome, err := retryOpen(&r, portLimit, func() (*udpSocket, error) {
				calls++
				if calls == 2 {
					clock += tc.elapsed // the first fresh attempt ends this late
				}
				return nil, tcpBindRefused
			})
			stats := r.stats()
			if !errors.Is(err, windows.WSAENOBUFS) || calls != tc.calls || outcome.Attempts != calls || !outcome.Refused ||
				stats["windowEnded"] != tc.ended || stats["finalFailures"] != uint64(1) {
				t.Fatalf("calls %d outcome %+v err %v stats %v", calls, outcome, err, stats)
			}
		})
	}
}

// The relay dial path end to end with injected refusals: attempts stop at the
// bound, the final refusal is counted once and recorded with its flow, and a
// refusal that a fresh attempt clears leaves no final refusal.
func TestTCPDialRetriesStopAtTheBoundAndRecordTheFlow(t *testing.T) {
	routes := &Routes{}
	routes.bindings.Store(&bindingTable{"line-1": {Up: true, Default4: true, Index4: 7,
		Addresses: []netip.Addr{netip.MustParseAddr("198.19.0.1")}}})
	refused := os.NewSyscallError("connectex", windows.WSAEADDRINUSE)
	calls, refuse := 0, 0
	d := &Dialer{Routes: routes, nativeDial: func(_ context.Context, _ Adapter, source netip.Addr, remote netip.AddrPort) (*readySocket, error) {
		calls++
		if calls <= refuse {
			return nil, refused
		}
		return &readySocket{}, nil
	}}
	flow := platform.FlowIdentity{Owner: platform.Owner{PID: 7, Path: `C:\apps\pinned.exe`, AppID: "pinned"},
		Source: netip.MustParseAddrPort("198.18.0.1:50000")}
	remote := netip.MustParseAddrPort("198.19.128.2:25000")

	refuse = 100
	if _, err := d.DialFlowTCP(context.Background(), "line-1", remote, flow); !errors.Is(err, windows.WSAEADDRINUSE) {
		t.Fatalf("dial = %v, want the refusal", err)
	}
	stats, refusals := d.tcpRetries.stats(), d.refusals.stats()
	recent := refusals["recent"].([]finalRefusal)
	if calls != 1+freshAttempts || stats["firstRefusals"] != uint64(1) || stats["freshAttempts"] != uint64(freshAttempts) ||
		stats["finalFailures"] != uint64(1) || len(recent) != 1 {
		t.Fatalf("%d calls, stats %v, refusals %+v", calls, stats, recent)
	}
	if r := recent[0]; r.Protocol != "tcp" || r.Kind != "flow" || r.AppID != "pinned" || r.PID != 7 || r.Source != "198.18.0.1:50000" ||
		r.Destination != remote.String() || r.Line != "line-1" || r.Local != "198.19.0.1:0" || r.Call != "connectex" || r.Attempts != 1+freshAttempts {
		t.Fatalf("final refusal %+v", r)
	}

	calls, refuse = 0, 2
	if c, err := d.DialFlowTCP(context.Background(), "line-1", remote, flow); err != nil || c == nil {
		t.Fatalf("dial after two refusals = %v, %v", c, err)
	}
	stats = d.tcpRetries.stats()
	if calls != 3 || stats["firstRefusals"] != uint64(2) || stats["finalFailures"] != uint64(1) ||
		stats["recoveredOnFreshAttempt"].([]uint64)[1] != 1 || d.refusals.stats()["count"] != uint64(1) {
		t.Fatalf("%d calls, stats %v", calls, stats)
	}

	// A fresh attempt that gets its port and is then refused by the peer is
	// not a final port refusal: neither counted for the gate nor recorded.
	calls = 0
	d.nativeDial = func(context.Context, Adapter, netip.Addr, netip.AddrPort) (*readySocket, error) {
		calls++
		if calls == 1 {
			return nil, refused
		}
		return nil, os.NewSyscallError("connectex", windows.WSAECONNREFUSED)
	}
	if _, err := d.DialFlowTCP(context.Background(), "line-1", remote, flow); !errors.Is(err, windows.WSAECONNREFUSED) {
		t.Fatalf("dial = %v, want the peer's refusal", err)
	}
	stats = d.tcpRetries.stats()
	if calls != 2 || stats["firstRefusals"] != uint64(3) || stats["finalFailures"] != uint64(1) || stats["otherFailures"] != uint64(1) ||
		d.refusals.stats()["count"] != uint64(1) {
		t.Fatalf("%d calls, stats %v, %v refusals recorded", calls, stats, d.refusals.stats()["count"])
	}
}

// A final refusal names the flow it hit: owner, app endpoint, destination,
// line, refusing call and errno. The list keeps the last 16.
func TestFinalPortRefusalsNameTheirFlow(t *testing.T) {
	var f finalRefusals
	owner := platform.Owner{PID: 4242, Path: `C:\apps\pinned.exe`, AppID: "pinned"}
	flow := platform.FlowIdentity{Owner: owner, Source: netip.MustParseAddrPort("198.18.0.1:50000"), Destination: netip.MustParseAddrPort("198.19.128.2:25000")}
	for i := range 20 {
		err := error(os.NewSyscallError("connectex", windows.WSAEADDRINUSE))
		kind := "flow"
		if i == 19 {
			err, kind = os.NewSyscallError("bind", windows.WSAENOBUFS), "probe"
		}
		f.record("tcp", kind, "line-1", netip.MustParseAddrPort("198.19.0.1:0"), flow, 5, err)
	}
	stats := f.stats()
	recent := stats["recent"].([]finalRefusal)
	if stats["count"] != uint64(20) || len(recent) != 16 {
		t.Fatalf("count %v, %d recent", stats["count"], len(recent))
	}
	last := recent[15]
	if last.Kind != "probe" || last.Call != "bind" || last.Errno != uint32(windows.WSAENOBUFS) || last.App != owner.Path || last.AppID != "pinned" ||
		last.PID != 4242 || last.Source != "198.18.0.1:50000" || last.Destination != "198.19.128.2:25000" || last.Line != "line-1" || last.Attempts != 5 {
		t.Fatalf("last refusal %+v", last)
	}
	if first := recent[0]; first.Call != "connectex" || first.Errno != uint32(windows.WSAEADDRINUSE) || first.Kind != "flow" {
		t.Fatalf("oldest kept refusal %+v", first)
	}
}
