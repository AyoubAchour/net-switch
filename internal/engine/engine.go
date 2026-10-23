// Package engine wires the platform-independent data path. OS resources enter
// only through injected interfaces; this package never discovers or opens them.
package engine

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"runtime/debug"
	"runtime/metrics"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"github.com/AyoubAchour/net-switch/internal/engine/flowapi"
	"github.com/AyoubAchour/net-switch/internal/engine/flows"
	"github.com/AyoubAchour/net-switch/internal/engine/platform"
	"github.com/AyoubAchour/net-switch/internal/engine/policy"
	ns "github.com/AyoubAchour/net-switch/internal/engine/stack"
	ntcp "github.com/AyoubAchour/net-switch/internal/engine/tcp"
	"github.com/AyoubAchour/net-switch/internal/engine/testproxy"
	"github.com/AyoubAchour/net-switch/internal/engine/udp"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	gv "gvisor.dev/gvisor/pkg/tcpip/stack"
)

type Dependencies struct {
	HealthKey  []byte
	OpenTun    func(context.Context) (platform.TunDevice, error)
	Routes     platform.RouteManager
	Dialer     platform.LineDialer
	Owners     platform.OwnerLookup
	Identities platform.UDPIdentity
	// SilentSYNDiagnostics records SYNs answered with neither a dial nor a
	// reset (stats tcpSilentSYN). Windows opts in; off, the TCP ingress path
	// does no work for them.
	SilentSYNDiagnostics bool
}
type Engine struct {
	// OnTunError may hand a platform-specific terminal condition to the service.
	// It runs under mu and must not block or call Engine methods. Returning true
	// transfers responsibility for Stop to the service; other errors retain the
	// ordinary cleanup and OnFatal path. Install before starting the engine.
	OnTunError func(error) bool

	OnFatal    func(error)
	mu         sync.Mutex
	root       context.Context
	deps       Dependencies
	Table      *flows.Table
	limits     flows.Limits
	cancel     context.CancelFunc
	tun        platform.TunDevice
	stack      *gv.Stack
	link       *ns.Link
	tcp        *ntcp.Forwarder
	udp        *udp.NAT
	testProxy  *testproxy.Server
	health     *forwardingCheck
	healthInfo atomic.Pointer[forwardingInfo]
	pumps      sync.WaitGroup
	lastError  error
	lines      []platform.Line
	live       atomic.Pointer[liveState]
}

type liveState struct {
	status    string
	started   time.Time
	lastError string
}

func (e *Engine) LastError() string {
	if s := e.live.Load(); s != nil {
		return s.lastError
	}
	return ""
}

// LiveState is independent of the engine mutation lock. Status and lease
// traffic must remain readable while a start/apply/stop is waiting on I/O.
func (e *Engine) LiveState() (string, time.Time) {
	if s := e.live.Load(); s != nil {
		return s.status, s.started
	}
	return "off", time.Time{}
}

func New(ctx context.Context, d Dependencies, l flows.Limits, state flows.StateStore) *Engine {
	e := &Engine{root: ctx, deps: d, limits: l, Table: flows.New(l, state)}
	if r, ok := d.Routes.(interface{ SetLineUse(func(string) bool) }); ok {
		r.SetLineUse(e.Table.ReferencesLine)
	}
	return e
}

func (e *Engine) Start(ctx context.Context, r policy.Revision) (policy.Applied, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.stack != nil {
		return e.applyLocked(ctx, r)
	}
	if e.deps.OpenTun == nil || e.deps.Routes == nil || e.deps.Owners == nil || e.deps.Dialer == nil {
		return policy.Applied{}, platform.ErrNotYet
	}
	if _, err := policy.Compile(r); err != nil {
		return policy.Applied{}, err
	}
	e.live.Store(&liveState{status: "starting"})
	e.lastError = nil
	debug.SetMemoryLimit(512 << 20)
	tun, err := e.deps.OpenTun(ctx)
	if err != nil {
		e.lastError = err
		e.live.Store(&liveState{status: "error", lastError: Clip(err.Error(), 4096)})
		return policy.Applied{}, err
	}
	e.tun = tun
	rollback := func(err error) (policy.Applied, error) {
		e.lastError = err
		cleanup := e.stopLocked(context.WithoutCancel(ctx))
		return policy.Applied{}, errors.Join(err, cleanup)
	}
	if tun.MTU() != ns.MTU {
		return rollback(fmt.Errorf("TUN MTU must be %d", ns.MTU))
	}
	if err := e.deps.Routes.Prepare(ctx, r.Config.Lines); err != nil {
		return rollback(err)
	}
	a, err := e.Table.Apply(r)
	if err != nil {
		return rollback(err)
	}
	e.lines = cloneLines(r.Config.Lines)
	link := ns.NewLink()
	s, err := ns.New(link, ns.DefaultOptions())
	if err != nil {
		return rollback(err)
	}
	e.link = link
	e.stack = s
	if err := e.startForwardingCheck(); err != nil {
		return rollback(err)
	}
	// A disconnected controller does not own the forwarding lifetime. The
	// service context and protocol lease do; reattach keeps these flows alive.
	run, cancel := context.WithCancel(e.root)
	e.cancel = cancel
	if device, ok := tun.(platform.TunIOContext); ok {
		device.BindIOContext(run)
	}
	e.tcp = ntcp.New(run, s, e.limits.Handshakes, e.Table, e.deps.Owners, e.deps.Dialer, link)
	if e.deps.SilentSYNDiagnostics {
		e.tcp.RecordSilentSYNs() // before the pumps below deliver any packet
	}
	e.udp = udp.New(run, s, e.Table, e.deps.Owners, e.deps.Identities, e.deps.Dialer, link, tun.MTU())
	echo := newEcho(run, e.deps.Dialer, e.Table, link)
	nat := e.udp
	if events, ok := e.deps.Identities.(platform.UDPNotifications); ok {
		e.pumps.Go(func() { events.WatchUDP(run, nat.Destroy, nat.RefreshNow) })
	}
	link.SetObserver(func(p *gv.PacketBuffer) {
		first, ok := p.Data().PullUp(20)
		if !ok {
			return
		}
		if (first[0]>>4 == 4 && first[9] != 1) || (first[0]>>4 == 6 && first[6] != 58) {
			return
		}
		b := p.Data().AsRange().ToSlice()
		nat.ObserveICMP(b)
	})
	e.pumps.Go(func() {
		defer echo.wait()
		b := make([]byte, ns.MTU)
		for {
			n, err := tun.ReadPacket(run, b)
			if err != nil {
				if run.Err() == nil {
					e.fail(link, err)
				}
				return
			}
			if n <= 0 || n > len(b) {
				continue
			}
			if echo.handle(b[:n]) {
				continue
			}
			proto := header.IPv4ProtocolNumber
			if b[0]>>4 == 6 {
				proto = header.IPv6ProtocolNumber
			} else if b[0]>>4 != 4 {
				continue
			}
			// MakeWithData copies into a gVisor-owned chunk before returning.
			// An extra clone here doubles ingress payload allocations.
			p := gv.NewPacketBuffer(gv.PacketBufferOptions{Payload: buffer.MakeWithData(b[:n])})
			if verified, ok := tun.(platform.ChecksumVerifier); ok {
				p.RXChecksumValidated = verified.RXChecksumVerified(b[:n])
			}
			link.InjectInbound(proto, p)
			p.DecRef()
		}
	})
	e.pumps.Go(func() {
		packets := make([][]byte, 64)
		owned := make([]ns.OutputPacket, len(packets))
		for {
			n := link.ReadOwnedBatch(run, owned)
			if n == 0 {
				return
			}
			for i := range n {
				packets[i] = owned[i].Bytes
			}
			var err error
			if batch, ok := tun.(platform.BatchWriter); ok {
				_, err = batch.WriteBatch(packets[:n])
			} else {
				for _, p := range packets[:n] {
					if err = tun.WritePacket(run, p); err != nil {
						break
					}
				}
			}
			for i := range n {
				owned[i].Release()
			}
			clear(packets[:n])
			if err != nil {
				if run.Err() == nil {
					e.fail(link, err)
				}
				return
			}
		}
	})
	if err := e.deps.Routes.Capture(ctx); err != nil {
		return rollback(err)
	}
	e.live.Store(&liveState{status: "on", started: time.Now()})
	return a, nil
}
func (e *Engine) fail(link *ns.Link, err error) {
	go func() {
		e.mu.Lock()
		defer e.mu.Unlock()
		if e.link != link {
			return
		}
		if e.OnTunError != nil && e.OnTunError(err) {
			e.lastError = err
			e.live.Store(&liveState{status: "stopping", lastError: Clip(err.Error(), 4096)})
			return
		}
		e.lastError = err
		cleanup := e.stopLocked(context.Background())
		e.lastError = errors.Join(err, cleanup)
		e.Table.Emit(flowapi.Event{Type: "fatal", Message: e.lastError.Error()})
		if e.OnFatal != nil {
			e.OnFatal(e.lastError)
		}
	}()
}
func (e *Engine) Apply(ctx context.Context, r policy.Revision) (policy.Applied, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.stack == nil {
		return policy.Applied{}, flows.ErrStopped
	}
	return e.applyLocked(ctx, r)
}
func (e *Engine) applyLocked(ctx context.Context, r policy.Revision) (policy.Applied, error) {
	if old := e.Table.Applied(); old != nil && r.N <= old.N {
		return e.Table.Apply(r)
	}
	if _, err := policy.Compile(r); err != nil {
		return policy.Applied{}, err
	}
	// The platform contract makes Prepare transactional and keeps old flow
	// routes usable. Only explicit selectors close existing connections.
	if err := e.deps.Routes.Prepare(ctx, r.Config.Lines); err != nil {
		return policy.Applied{}, err
	}
	a, err := e.Table.Apply(r)
	if err != nil {
		rollback := e.deps.Routes.Prepare(context.WithoutCancel(ctx), e.lines)
		if rollback != nil {
			e.stopLocked(context.WithoutCancel(ctx))
		}
		return policy.Applied{}, errors.Join(err, rollback)
	}
	e.lines = cloneLines(r.Config.Lines)
	if err == nil && !r.Config.IPv6 {
		e.Table.CloseFlows(flows.Selector{IPv6: true}, a.Point)
	}
	return a, err
}
func (e *Engine) Stop(ctx context.Context) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.stopLocked(ctx)
}
func (e *Engine) stopLocked(ctx context.Context) error {
	lastError := e.LastError()
	e.live.Store(&liveState{status: "stopping", lastError: lastError})
	phase := func(string) func() { return func() {} }
	if timing, ok := e.deps.Routes.(interface{ StopPhase(string) func() }); ok {
		phase = timing.StopPhase
	}
	finish := phase("quiesce")
	if routes, ok := e.deps.Routes.(platform.RouteQuiescer); ok {
		routes.Quiesce()
	}
	finish()
	finish = phase("flow-close")
	if e.cancel != nil {
		e.cancel()
	}
	if e.testProxy != nil {
		e.testProxy.Close()
		e.testProxy = nil
	}
	if e.health != nil {
		e.health.Close()
		e.health = nil
	}
	e.healthInfo.Store(nil)
	e.Table.Unload()
	e.Table.CloseAll()
	finish()
	finish = phase("tcp-stop")
	if e.tcp != nil {
		e.tcp.Stop()
	}
	finish()
	finish = phase("stack-close")
	if e.stack != nil {
		e.stack.Close()
	}
	finish()
	finish = phase("udp-close")
	if e.udp != nil {
		e.udp.Close()
	}
	finish()
	finish = phase("tun-signal")
	beginTun := func() {}
	joinTun := func() error { return nil }
	if e.tun != nil {
		if starter, ok := e.tun.(platform.TunCloseStarter); ok {
			// The cancelled I/O context wakes the pumps. Complete socket
			// cancellation before native device teardown; device close still
			// overlaps the journal's fingerprint checks and route cleanup.
			beginTun = starter.BeginClose
			joinTun = e.tun.Close
		} else {
			e.tun.Close()
		}
	}
	finish()
	finish = phase("pumps-join")
	e.pumps.Wait()
	finish()
	finish = phase("stack-join")
	if e.stack != nil {
		e.stack.Wait()
	}
	finish()
	finish = phase("tcp-join")
	if e.tcp != nil {
		e.tcp.Wait()
	}
	finish()
	finish = phase("tun-begin")
	beginTun()
	finish()
	finish = phase("link-close")
	if e.link != nil {
		e.link.Close()
	}
	finish()
	e.stack = nil
	e.tcp = nil
	e.udp = nil
	e.link = nil
	e.tun = nil
	e.cancel = nil
	e.lines = nil
	var cleanup error
	if e.deps.Routes != nil {
		cleanup = e.deps.Routes.Cleanup(ctx)
	}
	err := errors.Join(cleanup, joinTun())
	status := "off"
	if err != nil {
		e.lastError = errors.Join(e.lastError, err)
	}
	if e.lastError != nil {
		status = "error"
		lastError = Clip(e.lastError.Error(), 4096)
	}
	e.live.Store(&liveState{status: status, lastError: lastError})
	return err
}

func cloneLines(lines []platform.Line) []platform.Line {
	out := append([]platform.Line(nil), lines...)
	for i := range out {
		out[i].Addresses = append(out[i].Addresses[:0:0], out[i].Addresses...)
	}
	return out
}
func (e *Engine) Stats() any {
	e.mu.Lock()
	defer e.mu.Unlock()
	// Aggregates only: every entry has a fixed bound (see stats_bound_test.go).
	// Per-flow detail is in the paged flows listing.
	s := map[string]any{"flows": e.Table.Stats()}
	if tun, ok := e.tun.(interface{ Stats() any }); ok {
		s["tunKernel"] = tun.Stats()
	}
	if owners, ok := e.deps.Owners.(interface{ Stats() any }); ok {
		s["ownerLookup"] = owners.Stats()
	}
	if dialer, ok := e.deps.Dialer.(interface{ Stats() any }); ok {
		s["dialer"] = dialer.Stats()
	}
	var memory runtime.MemStats
	runtime.ReadMemStats(&memory)
	s["heapBytes"] = memory.HeapAlloc
	s["stackBytes"] = memory.StackInuse
	s["heapGoalBytes"] = memory.NextGC
	s["gcCycles"] = uint64(memory.NumGC)
	s["gcCPUppm"] = uint64(memory.GCCPUFraction * 1_000_000)
	s["runtimeBytes"] = memory.Sys - memory.HeapReleased
	s["goroutines"] = uint64(runtime.NumGoroutine())
	s["gomaxprocs"] = uint64(runtime.GOMAXPROCS(0))
	samples := []metrics.Sample{{Name: "/gc/stack/starting-size:bytes"}, {Name: "/gc/heap/live:bytes"}, {Name: "/cpu/classes/gc/total:cpu-seconds"}, {Name: "/cpu/classes/total:cpu-seconds"}}
	metrics.Read(samples)
	s["stackStartBytes"] = samples[0].Value.Uint64()
	s["heapLiveBytes"] = samples[1].Value.Uint64()
	s["gcCPUNanos"] = uint64(samples[2].Value.Float64() * 1e9)
	s["totalCPUNanos"] = uint64(samples[3].Value.Float64() * 1e9)
	if e.lastError != nil {
		s["fatal"] = Clip(e.lastError.Error(), 4096)
	}
	if e.link != nil {
		s["tunDropped"] = e.link.Dropped.Load()
		for kind, count := range e.link.DropCounts() {
			s["tunDropped."+kind] = count
		}
		s["tunQueued"] = e.link.Queued()
		s["tunPeakQueued"] = e.link.PeakQueued()
	}
	if e.tcp != nil {
		s["tcpRelayBytes"], s["tcpRelayPeakBytes"] = e.tcp.RelayBufferBytes()
		s["tcpRejected"] = e.tcp.Rejected.Load()
		s["tcpInvalid"] = e.tcp.Invalid.Load()
		s["tcpDialFailed"] = e.tcp.DialFailed.Load()
		if silent := e.tcp.SilentStats(); silent != nil {
			s["tcpSilentSYN"] = silent
		}
		s["tcpFlows"], s["tcpFlowsOmitted"] = e.tcp.Diagnostics(128)
	}
	if e.stack != nil {
		stats := e.stack.Stats()
		s["tcpSegmentsSent"] = stats.TCP.SegmentsSent.Value()
		s["tcpRetransmits"] = stats.TCP.Retransmits.Value()
		s["tcpRTOs"] = stats.TCP.Timeouts.Value()
		s["tcpSACKRecoveries"] = stats.TCP.SACKRecovery.Value()
		s["tcpSpuriousRTOs"] = stats.TCP.SpuriousRTORecovery.Value()
		s["transportDropped"] = stats.DroppedPackets.Value()
	}
	if e.udp != nil {
		s["udpRejected"] = e.udp.Rejected.Load()
		s["udpInvalid"] = e.udp.Invalid.Load()
		s["udpDropped"] = e.udp.Dropped.Load()
		s["udpIdentityErrors"] = e.udp.IdentityErrors.Load()
		s["udpOversize"] = e.udp.Oversize.Load()
		s["udpReadErrors"] = e.udp.ReadErrors.Load()
		s["udpOpenFailed"] = e.udp.OpenFailed.Load()
		s["udpGenerationMissing"] = e.udp.GenerationMissing.Load()
		s["udpRefusalDatagrams"] = e.udp.RefusalStats()
		s["udpReconcileIdentityFallbacks"] = e.udp.ReconcileIdentityFallbacks.Load()
		s["udpNegativeEntries"] = uint64(e.udp.NegativeCacheSize())
		s["udpPeakQueuePackets"] = e.udp.PeakQueuePackets.Load()
		s["udpPeakQueueBytes"] = e.udp.PeakQueueBytes.Load()
	}
	return s
}

// Clip bounds a diagnostic string in the stats reply to n bytes, keeping a
// UTF-8 boundary, and says how much was cut.
func Clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	cut := n
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut] + fmt.Sprintf("... (%d bytes cut)", len(s)-cut)
}
