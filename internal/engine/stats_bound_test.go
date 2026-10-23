package engine

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net"
	"net/netip"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/AyoubAchour/net-switch/internal/engine/flowapi"
	"github.com/AyoubAchour/net-switch/internal/engine/flows"
	"github.com/AyoubAchour/net-switch/internal/engine/platform"
	"github.com/AyoubAchour/net-switch/internal/engine/policy"
	"github.com/AyoubAchour/net-switch/internal/engine/protocol"
	ntcp "github.com/AyoubAchour/net-switch/internal/engine/tcp"
	"github.com/AyoubAchour/net-switch/internal/engine/testfake"
	"github.com/AyoubAchour/net-switch/internal/engine/udp"
)

// widestStats is Engine.Stats with its bounded lists at their bounds and
// widest values, however the run got there: 128 TCP diagnostics (listed only
// up to 128 connections) and 32 silent SYNs.
type widestStats struct {
	*Engine
	t *testing.T
}

func (w widestStats) Stats() any {
	s := w.Engine.Stats().(map[string]any)
	var flow ntcp.Diagnostic
	fields := reflect.ValueOf(&flow).Elem()
	for i := range fields.NumField() {
		switch field := fields.Field(i); {
		case field.Kind() == reflect.String:
			field.SetString("[ffff:ffff:ffff:ffff:ffff:ffff:ffff:fffe]:65535")
		case field.Kind() == reflect.Bool:
			field.SetBool(false)
		case field.CanInt():
			field.SetInt(math.MinInt64 >> (64 - field.Type().Bits()))
		case field.CanUint():
			field.SetUint(math.MaxUint64 >> (64 - field.Type().Bits()))
		default:
			w.t.Fatalf("give TCP diagnostic field %s a widest value", fields.Type().Field(i).Name)
		}
	}
	s["tcpFlows"], s["tcpFlowsOmitted"] = slices.Repeat([]ntcp.Diagnostic{flow}, 128), 0
	silent := s["tcpSilentSYN"].(map[string]any)
	end := "[ffff:ffff:ffff:ffff:ffff:ffff:ffff:fffe]:65535"
	silent["recent"] = slices.Repeat([]ntcp.SilentSYN{{AtUnixMilli: math.MaxInt64, Source: end, Destination: end, Reason: "live-connection"}}, 32)
	for reason := range silent["counts"].(map[string]uint64) {
		silent["counts"].(map[string]uint64)[reason] = math.MaxUint64
	}
	return s
}

// SYSTEM-DESIGN 5.10: stats is one control reply under protocol.MessageLimit,
// so every entry needs a bound that load cannot move. Linux acceptance job
// 119720908293 failed when the reply listed every handshake with its owner.
// This fills the flow table to every limit (65,536 flows, 8,192 handshakes,
// 16,384 UDP sessions, 8,192 per app) with the longest owners the table
// accepts, puts the bounded lists at their bounds and a 1 MiB fatal error in
// place, and sends the real stats reply: it must fit in a quarter of the
// limit, the rest being the platforms' own sections (tested beside them).
func TestStatsReplyStaysBoundedAtEveryLimit(t *testing.T) {
	l := flows.Defaults()
	l.Handshakes = 8192 // Linux's limit, the larger
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	// With every opt-in section on, as on Windows.
	e := New(ctx, Dependencies{OpenTun: func(context.Context) (platform.TunDevice, error) { return testfake.NewTun(), nil },
		Routes: &testfake.Routes{}, Dialer: testfake.Dialer{}, Owners: &testfake.Owners{}, SilentSYNDiagnostics: true}, l, nil)
	c := policy.Config{Lines: []platform.Line{{ID: strings.Repeat("L", 64)}}}
	if _, err := e.Start(ctx, policy.Revision{N: 1, Hash: policy.Hash(c), Config: c}); err != nil {
		t.Fatal(err)
	}
	defer e.Stop(context.Background())

	apps := l.Flows / l.PerApp
	owners := make([]platform.Owner, apps)
	for i := range owners {
		id := fmt.Sprintf("app%d-", i)
		owners[i] = platform.Owner{PID: math.MaxUint32, StartTime: math.MaxUint64, Path: strings.Repeat("p", 1024),
			AppID: id + strings.Repeat("a", 512-len(id)), Generation: strings.Repeat("g", 256)}
	}
	var tickets []flowapi.Ticket
	defer func() {
		for _, x := range tickets {
			x.Close()
		}
	}()
	admit := func(n int, protocol string, established bool) {
		for i := range n {
			source := netip.AddrPortFrom(netip.AddrFrom4([4]byte{198, 18, byte(len(tickets) >> 8), byte(len(tickets))}), 40000)
			x, err := e.Table.Begin(protocol, platform.Tuple{Source: source, Destination: netip.MustParseAddrPort("203.0.113.7:443")})
			if err != nil {
				t.Fatalf("%s flow %d: %v (%+v)", protocol, i, err, e.Table.Stats())
			}
			tickets = append(tickets, x)
			if _, err := x.Resolve(owners[len(tickets)%apps]); err != nil {
				t.Fatalf("%s flow %d: %v", protocol, i, err)
			}
			if established {
				x.Established(netip.MustParseAddr("192.0.2.1"))
			}
		}
	}
	// Every TCP flow begins as a handshake: established ones first.
	admit(l.UDP, "udp", true)
	admit(l.Flows-l.UDP-l.Handshakes, "tcp", true)
	admit(l.Handshakes, "tcp", false)
	if _, err := e.Table.Begin("tcp", platform.Tuple{Source: netip.MustParseAddrPort("198.18.255.255:1"), Destination: netip.MustParseAddrPort("203.0.113.7:443")}); !errors.Is(err, flows.ErrBudget) {
		t.Fatalf("a flow past the limit: %v", err)
	}
	g := e.Table.Stats()
	if g.Flows != l.Flows || g.Handshakes != l.Handshakes || g.UDP != l.UDP || g.PeakPerApp != l.PerApp {
		t.Fatalf("not at every limit: %d flows, %d handshakes, %d UDP, %d per app", g.Flows, g.Handshakes, g.UDP, g.PeakPerApp)
	}
	e.mu.Lock()
	e.lastError = errors.New(strings.Repeat("x", 1<<20))
	e.mu.Unlock()

	// The per-flow handshake detail 5b502222 put into stats, as the full
	// listing now carries it: far past one reply at this size.
	detail := 0
	for page, err := e.Table.PageAll(""); ; page, err = e.Table.PageAll(page.Cursor) {
		if err != nil {
			t.Fatal(err)
		}
		for _, r := range page.Flows {
			if r.Handshake {
				b, _ := json.Marshal(r)
				detail += len(b) + 1
			}
		}
		if page.Cursor == "" {
			break
		}
	}
	if detail <= protocol.MessageLimit {
		t.Fatalf("listing every handshake takes %d bytes; the fixture must reproduce the old overflow", detail)
	}

	line := statsReply(t, protocol.New(widestStats{Engine: e, t: t}, e.Table, nil))
	var reply struct {
		Result struct {
			Engine struct {
				Flows          flows.Gauges   `json:"flows"`
				Fatal          string         `json:"fatal"`
				TCPFlows       []any          `json:"tcpFlows"`
				OmittedForSize map[string]int `json:"omittedForSize"`
			} `json:"engine"`
		} `json:"result"`
	}
	if err := json.Unmarshal(line, &reply); err != nil {
		t.Fatal(err)
	}
	got := reply.Result.Engine
	if got.Flows.Flows != l.Flows || len(got.TCPFlows) != 128 || len(got.Fatal) > 4096+64 || got.OmittedForSize != nil {
		t.Fatalf("reply: %d flows, %d TCP diagnostics, %d-byte fatal, omitted %v", got.Flows.Flows, len(got.TCPFlows), len(got.Fatal), got.OmittedForSize)
	}
	budget := protocol.MessageLimit / 4
	t.Logf("stats reply at every flow limit: %d bytes + %d reserved for the full refusal ring = %d; shared budget %d (handshake detail would be %d)",
		len(line), udp.RefusalStatsBudget, len(line)+udp.RefusalStatsBudget, budget, detail)
	if len(line)+udp.RefusalStatsBudget > budget {
		t.Fatalf("the shared stats reply takes %d bytes plus %d reserved for refusal evidence; keep it within %d", len(line), udp.RefusalStatsBudget, budget)
	}
}

// statsReply attaches to server over a pipe and returns its stats reply line.
func statsReply(t *testing.T, server *protocol.Server) []byte {
	t.Helper()
	controller, transport := net.Pipe()
	if err := controller.SetDeadline(time.Now().Add(30 * time.Second)); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	served := make(chan error, 1)
	go func() { served <- server.Serve(ctx, transport) }()
	defer func() {
		cancel()
		controller.Close()
		<-served
	}()
	replies := bufio.NewReader(controller)
	var line []byte
	for _, request := range []protocol.Request{
		{ID: "attach", Method: "attach", Instance: server.Instance},
		{ID: "stats", Method: "stats", Instance: server.Instance, Epoch: 1},
	} {
		b, err := json.Marshal(request)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := controller.Write(append(b, '\n')); err != nil {
			t.Fatal(err)
		}
		if line, err = replies.ReadBytes('\n'); err != nil {
			t.Fatal(err)
		}
		var reply struct {
			ID    string `json:"id"`
			Error string `json:"error"`
		}
		if err := json.Unmarshal(line, &reply); err != nil || reply.ID != request.ID || reply.Error != "" {
			t.Fatalf("%s reply %q: error %q, %v", request.Method, reply.ID, reply.Error, err)
		}
	}
	return line
}
