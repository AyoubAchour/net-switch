//go:build windows

package winengine

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/netip"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/AyoubAchour/net-switch/internal/engine"
	"github.com/AyoubAchour/net-switch/internal/engine/flows"
	"github.com/AyoubAchour/net-switch/internal/engine/platform"
	"github.com/AyoubAchour/net-switch/internal/engine/protocol"
	"golang.org/x/sys/windows"
)

// The Windows sections of the stats reply, outside hosted CI's trace, each at
// its fixed bound with its widest values: 255 lines whose adapters list 40
// addresses with 300-character aliases, 16 owner-lookup failures, 32 slow and
// 32 running dials, 16 final port refusals with the longest owners, 32
// distinct send errors, 256 port settings and a 4 MiB worker error. With the
// shared reply's own budget (a quarter of the limit, tested in the engine
// package at every flow limit) they must still fit the stats budget, so no
// section is ever left out for size outside a trace.
func TestWindowsStatsStayBoundedWithoutTrace(t *testing.T) {
	long := func(n int) string { return strings.Repeat("é", n) } // 2 bytes each in UTF-8
	address := netip.MustParseAddr("ffff:ffff:ffff:ffff:ffff:ffff:ffff:fffe")
	end := netip.AddrPortFrom(address, 65535)

	bindings := bindingTable{}
	for i := range 255 {
		var addresses []netip.Addr
		for range 40 {
			addresses = append(addresses, address)
		}
		bindings[fmt.Sprintf("{%08X-0000-0000-0000-000000000000}", i)] = Adapter{ID: "{FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF}", Alias: long(300),
			LUID: math.MaxUint64, Index4: math.MaxUint32, Index6: math.MaxUint32, Addresses: addresses, Valid: addresses, Up: true, MTU: math.MaxUint32, Metric: math.MaxUint32}
	}
	routes := &Routes{Instance: strings.Repeat("i", 32), timings: &phaseTimings{values: map[string]phaseTiming{}}}
	routes.bindings.Store(&bindings)
	for i := range 64 {
		routes.timings.values[fmt.Sprintf("engine.stop.phase-%02d-%s", i, strings.Repeat("n", 24))] = phaseTiming{math.MaxUint64, math.MaxUint64, math.MaxUint64}
	}

	owners := NewOwners()
	for range 20 {
		owners.noteFailure("tcp", "identity", end, long(300), errors.New(long(1<<14)))
	}

	d := &Dialer{Routes: routes, ports: newPortDiagnostics()}
	defer d.ports.close()
	huge := errors.New(strings.Repeat("w", 4<<20))
	d.ports.state, d.ports.err = "error", portConfigurationError(huge)
	maxPort := uint32(math.MaxUint32)
	for range 256 {
		d.ports.config = append(d.ports.config, portTemplate{SettingName: strings.Repeat("s", 64), DynamicPortRangeStartPort: &maxPort,
			DynamicPortRangeNumberOfPorts: &maxPort, AutoReusePortRangeStartPort: &maxPort, AutoReusePortRangeNumberOfPorts: &maxPort})
	}
	line := strings.Repeat("L", 64)
	for range 40 {
		note, _ := d.startDial(line, end)
		d.finishDial(note, time.Now().Add(-2*time.Second), nil, errors.New(long(1<<14)))
	}
	for range 40 {
		d.inFlight[&slowDial{AtUnixMilli: math.MaxInt64, Line: line, Remote: end.String()}] = time.Now().Add(-2 * time.Second)
	}
	owner := platform.Owner{PID: math.MaxUint32, Path: strings.Repeat("p", 2048), AppID: strings.Repeat("a", 1024)}
	for range 20 {
		d.refusals.record("tcp", "flow", line, end, platform.FlowIdentity{Owner: owner, Source: end, Destination: end}, freshAttempts+1,
			os.NewSyscallError("connectex", windows.WSAEADDRINUSE))
	}
	for i := range 40 {
		noteUDPSendFailure("bound", end, fmt.Errorf("wsasendto %d %s: %w", i, long(300), windows.WSAEHOSTUNREACH))
	}

	e := engine.New(context.Background(), engine.Dependencies{Dialer: d, Owners: owners}, flows.Defaults(), nil)
	r := &Runtime{Engine: e, routes: routes, owners: owners, dialer: d}
	stats := r.Stats().(map[string]any)
	if _, traced := stats["packetTrace"]; traced {
		t.Fatal("this test is about the untraced reply")
	}
	b, err := json.Marshal(stats)
	if err != nil {
		t.Fatal(err)
	}
	var reply struct {
		Bindings          map[string]Adapter `json:"bindings"`
		BindingsTruncated []string           `json:"bindingsTruncated"`
		SocketResources   struct {
			ConfigurationError string `json:"configurationError"`
		} `json:"socketResources"`
		Dialer struct {
			SlowRecent, SlowInFlight []slowDial
		} `json:"dialer"`
		FinalPortRefusals struct {
			Recent []finalRefusal `json:"recent"`
		} `json:"finalPortRefusals"`
		UDPSendFailures struct {
			ByError map[string]uint64 `json:"byError"`
		} `json:"udpSendFailures"`
		OwnerLookup LookupHistogram `json:"ownerLookup"`
	}
	if err := json.Unmarshal(b, &reply); err != nil {
		t.Fatal(err)
	}
	for id, a := range reply.Bindings {
		if len(a.Alias) > 256+32 || len(a.Addresses) != 8 || len(a.Valid) != 8 {
			t.Fatalf("binding %s kept a %d-byte alias and %d/%d addresses", id, len(a.Alias), len(a.Addresses), len(a.Valid))
		}
	}
	if len(reply.BindingsTruncated) != 255 || len(reply.SocketResources.ConfigurationError) > 4096+32 ||
		len(reply.Dialer.SlowRecent) != 32 || len(reply.Dialer.SlowInFlight) != 32 || len(reply.Dialer.SlowRecent[0].Error) > 512+32 ||
		len(reply.FinalPortRefusals.Recent) != 16 || len(reply.FinalPortRefusals.Recent[0].App) > 1024+32 || len(reply.FinalPortRefusals.Recent[0].AppID) > 512+32 ||
		len(reply.UDPSendFailures.ByError) > 32 || len(reply.OwnerLookup.Failures) != 16 || len(reply.OwnerLookup.Failures[0].Error) > 512+32 {
		t.Fatalf("a section is past its bound: %d truncated bindings, %d-byte port error, %d/%d dials, %d refusals, %d send errors, %d lookup failures",
			len(reply.BindingsTruncated), len(reply.SocketResources.ConfigurationError), len(reply.Dialer.SlowRecent), len(reply.Dialer.SlowInFlight),
			len(reply.FinalPortRefusals.Recent), len(reply.UDPSendFailures.ByError), len(reply.OwnerLookup.Failures))
	}
	shared := protocol.MessageLimit / 4
	t.Logf("Windows stats without trace at every bound: %d bytes; with the shared budget %d of %d", len(b), len(b)+shared, protocol.StatsBudget)
	if len(b)+shared > protocol.StatsBudget {
		t.Fatalf("Windows sections take %d bytes; with the shared %d they exceed the %d-byte stats budget", len(b), shared, protocol.StatsBudget)
	}
}
