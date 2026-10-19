//go:build windows

package main

import (
	"fmt"
	"io"
	"reflect"
	"runtime"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
)

type diagnosticEvent struct {
	At         int64             `json:"at"`
	Kind       string            `json:"kind"`
	Connection uint64            `json:"connection,omitempty"`
	Tuple      string            `json:"tuple,omitempty"`
	Detail     string            `json:"detail,omitempty"`
	Counters   map[string]uint64 `json:"counters"`
}

type heartbeatGap struct {
	From int64   `json:"from"`
	To   int64   `json:"to"`
	Ms   float64 `json:"ms"`
}

type watchedEndpoint struct {
	id       uint64
	tuple    string
	endpoint tcpip.Endpoint
	state    uint32
}

type diagnostics struct {
	sync.Mutex
	serial    uint64
	events    [1024]diagnosticEvent
	next      uint64
	endpoints []watchedEndpoint
	gaps      []heartbeatGap
	ticks     uint64
	maxGapMs  float64
	wire      map[string]uint64
}

func (g *gateway) tcpCounters() map[string]uint64 {
	stats := g.stack.Stats()
	result := map[string]uint64{"DroppedPackets": stats.DroppedPackets.Value(), "SessionWriteDrops": g.device.writeDrops.Load()}
	fields := reflect.ValueOf(stats.TCP)
	for i := 0; i < fields.NumField(); i++ {
		if counter, ok := fields.Field(i).Interface().(*tcpip.StatCounter); ok && counter != nil {
			result[fields.Type().Field(i).Name] = counter.Value()
		}
	}
	return result
}

func (g *gateway) event(kind string, id uint64, tuple, detail string) {
	stats := g.stack.Stats()
	e := diagnosticEvent{At: time.Now().UnixMicro(), Kind: kind, Connection: id, Tuple: tuple, Detail: detail,
		Counters: map[string]uint64{"retransmits": stats.TCP.Retransmits.Value(), "timeouts": stats.TCP.Timeouts.Value(),
			"dropped": stats.DroppedPackets.Value(), "invalid": stats.TCP.InvalidSegmentsReceived.Value(),
			"sendErrors": stats.TCP.SegmentSendErrors.Value(), "sessionWriteDrops": g.device.writeDrops.Load()}}
	g.diag.Lock()
	g.diag.events[g.diag.next%uint64(len(g.diag.events))] = e
	g.diag.next++
	g.diag.Unlock()
}

func (g *gateway) newConnection(id stack.TransportEndpointID) (uint64, string) {
	g.diag.Lock()
	g.diag.serial++
	serial := g.diag.serial
	g.diag.Unlock()
	tuple := fmt.Sprintf("%s:%d -> %s:%d", id.RemoteAddress, id.RemotePort, id.LocalAddress, id.LocalPort)
	g.event("forwarder-call", serial, tuple, "")
	return serial, tuple
}

func (g *gateway) watchEndpoint(id uint64, tuple string, ep tcpip.Endpoint) {
	g.diag.Lock()
	if len(g.diag.endpoints) == 64 {
		g.diag.endpoints = g.diag.endpoints[1:]
	}
	g.diag.endpoints = append(g.diag.endpoints, watchedEndpoint{id, tuple, ep, ep.State()})
	g.diag.Unlock()
	g.event("endpoint-state", id, tuple, tcp.EndpointState(ep.State()).String())
}

// State() is an atomic read. Observe at packet and relay boundaries as well as
// every heartbeat; no endpoint locks are taken from inside the stack callback.
func (g *gateway) states() {
	var changed []watchedEndpoint
	g.diag.Lock()
	for i := range g.diag.endpoints {
		p := &g.diag.endpoints[i]
		if state := p.endpoint.State(); state != p.state {
			p.state = state
			changed = append(changed, *p)
		}
	}
	g.diag.Unlock()
	for _, p := range changed {
		g.event("endpoint-state", p.id, p.tuple, tcp.EndpointState(p.state).String())
	}
}

func (g *gateway) heartbeat() {
	timer := time.NewTicker(time.Millisecond)
	defer timer.Stop()
	previous := time.Now()
	for {
		select {
		case <-g.done:
			return
		case <-timer.C:
			now := time.Now() // ticker timestamps hide scheduler delays; sample now.
			ms := float64(now.Sub(previous)) / float64(time.Millisecond)
			g.diag.Lock()
			g.diag.ticks++
			if ms > g.diag.maxGapMs {
				g.diag.maxGapMs = ms
			}
			if ms > 5 {
				if len(g.diag.gaps) == 512 {
					g.diag.gaps = g.diag.gaps[1:]
				}
				g.diag.gaps = append(g.diag.gaps, heartbeatGap{previous.UnixMicro(), now.UnixMicro(), ms})
			}
			g.diag.Unlock()
			previous = now
			g.states()
		}
	}
}

var getTCPStatistics = windows.NewLazySystemDLL("iphlpapi.dll").NewProc("GetTcpStatistics")

func (g *gateway) diagnosticSnapshot() map[string]any {
	// MIB_TCPSTATS has fifteen consecutive DWORD fields on both architectures.
	var tcpStats [15]uint32
	code, _, _ := getTCPStatistics.Call(uintptr(unsafe.Pointer(&tcpStats[0])))
	win := map[string]any{"error": code, "rtoMinMs": tcpStats[1], "rtoMaxMs": tcpStats[2], "segmentsRetransmitted": tcpStats[11], "segmentsIn": tcpStats[9], "segmentsOut": tcpStats[10]}
	win["segmentsInError"], win["resetsOut"] = tcpStats[12], tcpStats[13]
	row := windows.MibIfRow2{InterfaceLuid: g.device.adapter.LUID()}
	err := windows.GetIfEntry2Ex(windows.MibIfEntryNormal, &row)
	ring := map[string]any{"writeDrops": g.device.writeDrops.Load(), "readErrors": g.device.readErrors.Load(), "writeErrors": g.device.writeErrors.Load(),
		"inDiscards": row.InDiscards, "outDiscards": row.OutDiscards, "inErrors": row.InErrors, "outErrors": row.OutErrors}
	if err != nil {
		ring["error"] = err.Error()
	}
	var memory runtime.MemStats
	runtime.ReadMemStats(&memory)
	pauses := []heartbeatGap{}
	for i, end := range memory.PauseEnd {
		if end != 0 {
			pauses = append(pauses, heartbeatGap{int64(end-memory.PauseNs[i]) / 1000, int64(end) / 1000, float64(memory.PauseNs[i]) / 1e6})
		}
	}
	g.diag.Lock()
	defer g.diag.Unlock()
	start := uint64(0)
	if g.diag.next > uint64(len(g.diag.events)) {
		start = g.diag.next - uint64(len(g.diag.events))
	}
	events := make([]diagnosticEvent, 0, g.diag.next-start)
	for n := start; n < g.diag.next; n++ {
		events = append(events, g.diag.events[n%uint64(len(g.diag.events))])
	}
	return map[string]any{"at": time.Now().UnixMicro(), "tcp": g.tcpCounters(), "windowsTCP": win, "ring": ring, "session": g.device.session.Stats(),
		"wire":   copyCounters(g.diag.wire),
		"events": events, "heartbeat": map[string]any{"periodMs": 1, "ticks": g.diag.ticks, "maxGapMs": g.diag.maxGapMs, "gaps": append([]heartbeatGap{}, g.diag.gaps...)},
		"gc": map[string]any{"count": memory.NumGC, "pauses": pauses}}
}

func copyCounters(values map[string]uint64) map[string]uint64 {
	result := make(map[string]uint64, len(values))
	for key, value := range values {
		result[key] = value
	}
	return result
}

type observedReader struct {
	io.Reader
	g                *gateway
	id               uint64
	tuple, direction string
	first            bool
}

func (r *observedReader) Read(buf []byte) (int, error) {
	n, err := r.Reader.Read(buf)
	if n > 0 && !r.first {
		r.first = true
		r.g.event("first-byte-"+r.direction, r.id, r.tuple, fmt.Sprint(n))
	}
	if err != nil {
		r.g.event("read-end-"+r.direction, r.id, r.tuple, err.Error())
	}
	return n, err
}
