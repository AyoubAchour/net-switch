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

	"github.com/AyoubAchour/net-switch/internal/engine/flowapi"
	"github.com/AyoubAchour/net-switch/internal/engine/flows"
	"github.com/AyoubAchour/net-switch/internal/engine/platform"
	"github.com/AyoubAchour/net-switch/internal/engine/policy"
	ns "github.com/AyoubAchour/net-switch/internal/engine/stack"
	ntcp "github.com/AyoubAchour/net-switch/internal/engine/tcp"
	"github.com/AyoubAchour/net-switch/internal/engine/udp"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	gv "gvisor.dev/gvisor/pkg/tcpip/stack"
)

type Dependencies struct {
	OpenTun    func(context.Context) (platform.TunDevice, error)
	Routes     platform.RouteManager
	Dialer     platform.LineDialer
	Owners     platform.OwnerLookup
	Identities platform.UDPIdentity
}
type Engine struct {
	OnFatal   func(error)
	mu        sync.Mutex
	root      context.Context
	deps      Dependencies
	Table     *flows.Table
	limits    flows.Limits
	cancel    context.CancelFunc
	tun       platform.TunDevice
	stack     *gv.Stack
	link      *ns.Link
	tcp       *ntcp.Forwarder
	udp       *udp.NAT
	pumps     sync.WaitGroup
	lastError error
	lines     []platform.Line
}

func New(ctx context.Context, d Dependencies, l flows.Limits, state flows.StateStore) *Engine {
	return &Engine{root: ctx, deps: d, limits: l, Table: flows.New(l, state)}
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
	debug.SetMemoryLimit(512 << 20)
	tun, err := e.deps.OpenTun(ctx)
	if err != nil {
		return policy.Applied{}, err
	}
	e.tun = tun
	rollback := func(err error) (policy.Applied, error) {
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
	// A disconnected controller does not own the forwarding lifetime. The
	// service context and protocol lease do; reattach keeps these flows alive.
	run, cancel := context.WithCancel(e.root)
	e.cancel = cancel
	if device, ok := tun.(platform.TunIOContext); ok {
		device.BindIOContext(run)
	}
	e.tcp = ntcp.New(run, s, e.limits.Handshakes, e.Table, e.deps.Owners, e.deps.Dialer, link)
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
	return a, nil
}
func (e *Engine) fail(link *ns.Link, err error) {
	go func() {
		e.mu.Lock()
		defer e.mu.Unlock()
		if e.link != link {
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
	if routes, ok := e.deps.Routes.(platform.RouteQuiescer); ok {
		routes.Quiesce()
	}
	if e.cancel != nil {
		e.cancel()
	}
	e.Table.Unload()
	e.Table.CloseAll()
	if e.tcp != nil {
		e.tcp.Stop()
	}
	if e.stack != nil {
		e.stack.Close()
	}
	if e.udp != nil {
		e.udp.Close()
	}
	if e.tun != nil {
		e.tun.Close()
	}
	e.pumps.Wait()
	if e.stack != nil {
		e.stack.Wait()
	}
	if e.tcp != nil {
		e.tcp.Wait()
	}
	if e.link != nil {
		e.link.Close()
	}
	e.stack = nil
	e.tcp = nil
	e.udp = nil
	e.link = nil
	e.tun = nil
	e.cancel = nil
	e.lines = nil
	if e.deps.Routes != nil {
		return e.deps.Routes.Cleanup(ctx)
	}
	return nil
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
	s := map[string]any{"flows": e.Table.Stats()}
	if tun, ok := e.tun.(interface{ Stats() any }); ok {
		s["tunKernel"] = tun.Stats()
	}
	if owners, ok := e.deps.Owners.(interface{ Stats() any }); ok {
		s["ownerLookup"] = owners.Stats()
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
	samples := []metrics.Sample{{Name: "/gc/stack/starting-size:bytes"}, {Name: "/gc/heap/live:bytes"}, {Name: "/cpu/classes/gc/total:cpu-seconds"}, {Name: "/cpu/classes/total:cpu-seconds"}}
	metrics.Read(samples)
	s["stackStartBytes"] = samples[0].Value.Uint64()
	s["heapLiveBytes"] = samples[1].Value.Uint64()
	s["gcCPUNanos"] = uint64(samples[2].Value.Float64() * 1e9)
	s["totalCPUNanos"] = uint64(samples[3].Value.Float64() * 1e9)
	if e.lastError != nil {
		s["fatal"] = e.lastError.Error()
	}
	if e.link != nil {
		s["tunDropped"] = e.link.Dropped.Load()
		s["tunQueued"] = e.link.Queued()
		s["tunPeakQueued"] = e.link.PeakQueued()
	}
	if e.tcp != nil {
		s["tcpRejected"] = e.tcp.Rejected.Load()
		s["tcpInvalid"] = e.tcp.Invalid.Load()
		s["tcpDialFailed"] = e.tcp.DialFailed.Load()
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
		s["udpPeakQueuePackets"] = e.udp.PeakQueuePackets.Load()
		s["udpPeakQueueBytes"] = e.udp.PeakQueueBytes.Load()
	}
	return s
}
