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
				name                string
				errs                []error
				calls               int
				first, fresh, final uint64
				recovered           []uint64
				wantErr             error
			}{
				{"first attempt", nil, 1, 0, 0, 0, []uint64{0, 0, 0, 0}, nil},
				{"other error is not retried", []error{denied}, 1, 0, 0, 0, []uint64{0, 0, 0, 0}, windows.WSAEACCES},
				{"second fresh attempt", []error{refused, refused}, 3, 1, 2, 0, []uint64{0, 1, 0, 0}, nil},
				{"every attempt refused", []error{refused, refused, refused, refused, refused, refused}, 5, 1, 4, 1, []uint64{0, 0, 0, 0}, refused},
				{"other error after a refusal ends it", []error{refused, denied}, 2, 1, 1, 1, []uint64{0, 0, 0, 0}, windows.WSAEACCES},
			} {
				t.Run(protocol.name+"/"+refused.Error()+"/"+tc.name, func(t *testing.T) {
					var r portRetries
					calls := 0
					s, attempts, err := retryOpen(&r, protocol.retryable, script(&calls, tc.errs...))
					if tc.wantErr == nil && (err != nil || s == nil) || tc.wantErr != nil && (!errors.Is(err, tc.wantErr) || s != nil) {
						t.Fatalf("open = %v, %v; want error %v", s, err, tc.wantErr)
					}
					stats := r.stats()
					if calls != tc.calls || attempts != calls || stats["firstRefusals"] != tc.first || stats["freshAttempts"] != tc.fresh || stats["finalFailures"] != tc.final {
						t.Fatalf("calls %d attempts %d stats %v", calls, attempts, stats)
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
	t.Run("time window", func(t *testing.T) {
		var r portRetries
		calls := 0
		_, _, err := retryOpen(&r, portLimit, func() (*udpSocket, error) {
			calls++
			if calls > 1 {
				time.Sleep(freshWindow)
			}
			return nil, tcpBindRefused
		})
		stats := r.stats()
		if !errors.Is(err, windows.WSAENOBUFS) || calls != 2 || stats["windowEnded"] != uint64(1) || stats["finalFailures"] != uint64(1) {
			t.Fatalf("calls %d err %v stats %v", calls, err, stats)
		}
	})
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
