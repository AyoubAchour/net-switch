// Package tcp admits connections before gVisor's silent forwarder limit.
package tcp

import (
	"context"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/AyoubAchour/net-switch/internal/engine/flowapi"
	"github.com/AyoubAchour/net-switch/internal/engine/packet"
	"github.com/AyoubAchour/net-switch/internal/engine/platform"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	gtcp "gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/waiter"
)

const DialTimeout = 10 * time.Second
const RelayBuffer = 32 << 10
const MinimumBuffer = 64 << 10

type Forwarder struct {
	ctx                           context.Context
	cancel                        context.CancelFunc
	mu                            sync.Mutex
	pending                       map[stack.TransportEndpointID]*pendingOpen
	wg                            sync.WaitGroup
	forwarder                     *gtcp.Forwarder
	stack                         *stack.Stack
	inFlight                      int
	connections                   map[stack.TransportEndpointID]*connection
	retired                       map[*connection]struct{}
	control                       flowapi.Controller
	owners                        platform.OwnerLookup
	dialer                        platform.LineDialer
	out                           flowapi.Output
	Rejected, Invalid, DialFailed atomic.Uint64
}

type orderedOutput interface {
	flowapi.Output
	SetAfterInbound(func())
}

func New(ctx context.Context, s *stack.Stack, inFlight int, control flowapi.Controller, owners platform.OwnerLookup, dialer platform.LineDialer, out orderedOutput) *Forwarder {
	ctx, cancel := context.WithCancel(ctx)
	f := &Forwarder{ctx: ctx, cancel: cancel, pending: make(map[stack.TransportEndpointID]*pendingOpen), connections: make(map[stack.TransportEndpointID]*connection), retired: make(map[*connection]struct{}), stack: s, inFlight: inFlight, control: control, owners: owners, dialer: dialer, out: out}
	f.forwarder = gtcp.NewForwarder(s, MinimumBuffer, 2*inFlight, f.open)
	s.SetTransportProtocolHandler(gtcp.ProtocolNumber, f.Handle)
	gtcp.SetTimeWaitHandler(s, f.Handle)
	drain := gtcp.SetLocalCloseFence(s, localCloseFenceEnabled)
	out.SetAfterInbound(func() {
		if ep := drain(); ep != nil {
			f.finishClose(ep)
		}
	})
	f.wg.Go(f.maintain)
	return f
}

func tuple(id stack.TransportEndpointID) platform.Tuple {
	src, _ := netip.AddrFromSlice(id.RemoteAddress.AsSlice())
	dst, _ := netip.AddrFromSlice(id.LocalAddress.AsSlice())
	return platform.Tuple{Source: netip.AddrPortFrom(src, id.RemotePort), Destination: netip.AddrPortFrom(dst, id.LocalPort)}
}

func (f *Forwarder) Handle(id stack.TransportEndpointID, p *stack.PacketBuffer) bool {
	h := header.TCP(p.TransportHeader().Slice())
	if len(h) < header.TCPMinimumSize {
		f.Invalid.Add(1)
		return true
	}
	_, valid, ok := header.TCPValid(h, p.Data().Checksum, uint16(p.Data().Size()), id.RemoteAddress, id.LocalAddress, false)
	if !valid || !ok {
		f.Invalid.Add(1)
		return true
	}
	if !h.Flags().Contains(header.TCPFlagSyn) || h.Flags()&(header.TCPFlagAck|header.TCPFlagRst|header.TCPFlagFin) != 0 {
		return false
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if c := f.connections[id]; c != nil {
		// State is atomic and Close is published after endpoint removal.
		// The hook can run under the old endpoint lock: never wait for that
		// lock or for the relay, which may itself need this TCP processor.
		state := gtcp.EndpointState(c.ep.State())
		// A TUN SYN can reach the default handler in the small gap between
		// unregister and StateClose. Check registration to cover that gap
		// without waiting on the endpoint lock.
		registered := f.stack.FindTransportEndpoint(p.NetworkProtocolNumber, gtcp.ProtocolNumber, id, p.NICID)
		if state == gtcp.StateClose || state == gtcp.StateError || any(registered) != any(c.ep) {
			c.ticket.Retire()
			select {
			case <-c.done:
				// Final accounting is ready; no need to retain this old graph.
				c.ticket.Close()
			default:
				f.retired[c] = struct{}{}
			}
			delete(f.connections, id)
		} else {
			// A delayed reopen callback can follow a duplicate SYN that has
			// already established the replacement. It must not reset or dial
			// that live incarnation a second time.
			return true
		}
	}
	if _, ok := f.pending[id]; ok {
		return true
	}
	if f.ctx.Err() != nil {
		return true
	}
	t := tuple(id)
	reject := func() {
		f.Rejected.Add(1)
		if f.control.AllowReject("") {
			f.out.Send(packet.Reset(t.Destination, t.Source, 0, h.SequenceNumber()+1+uint32(p.Data().Size()), true))
		}
	}
	// HandlePacket returns true for silent drops as well as queued requests.
	if len(f.pending) >= f.inFlight {
		reject()
		return true
	}
	ticket, err := f.control.Begin("tcp", t)
	if err != nil {
		reject()
		return true
	}
	f.pending[id] = &pendingOpen{ticket: ticket}
	f.wg.Add(1)
	dropped := f.stack.Stats().TCP.ForwardMaxInFlightDrop.Value()
	if !f.forwarder.HandlePacket(id, p) || f.stack.Stats().TCP.ForwardMaxInFlightDrop.Value() != dropped {
		delete(f.pending, id)
		ticket.Close()
		f.wg.Done()
		reject()
	}
	return true
}

func (f *Forwarder) open(r *gtcp.ForwarderRequest) {
	defer f.wg.Done()
	id := r.ID()
	f.mu.Lock()
	pending := f.pending[id]
	pending.request = r
	f.mu.Unlock()
	ticket := pending.ticket
	owned := true
	defer func() {
		if owned {
			ticket.Close()
		}
	}()
	// Complete exactly once, on every return path. Retain the deduplication
	// entry until Complete has removed gVisor's own in-flight entry.
	complete := func(reset bool) {
		f.complete(id, pending, reset)
	}
	discardHandshake := func() {
		if closeAdmissionEnabled {
			ticket.Retire()
		}
		complete(false)
	}
	owner := platform.Owner{}
	defer func() {
		if owned && closeAdmissionEnabled {
			ticket.Retire()
		}
		if !pending.completed.Load() {
			complete(f.control.AllowReject(owner.AppID))
		}
	}()
	ctx, cancel := context.WithCancel(f.ctx)
	defer cancel()
	ticket.SetCancel(cancel)
	t := tuple(id)
	lookup, cancelLookup := context.WithTimeout(ctx, 50*time.Millisecond)
	lookupStart := time.Now()
	var lookupErr error
	owner, lookupErr = f.owners.TCP(lookup, t)
	if observer, ok := f.control.(interface {
		Lookup(time.Duration, error, platform.Owner)
	}); ok {
		observer.Lookup(time.Since(lookupStart), lookupErr, owner)
	}
	if lookupErr != nil {
		owner = platform.Owner{}
	}
	cancelLookup()
	decision, err := ticket.Resolve(owner)
	if err != nil {
		f.Rejected.Add(1)
		return
	}
	dial, cancelDial := context.WithTimeout(ctx, DialTimeout)
	remote, err := f.dialer.DialTCP(dial, decision.Line, t.Destination)
	cancelDial()
	if err != nil {
		f.DialFailed.Add(1)
		if observer, ok := f.control.(interface{ LineError(string, error) }); ok && ctx.Err() == nil {
			observer.LineError(decision.Line, err)
		}
		return
	}
	defer remote.Close()
	stopRemote := context.AfterFunc(ctx, func() { remote.SetLinger(0); remote.Close() })
	defer stopRemote()
	if ctx.Err() != nil {
		return
	}
	var wq waiter.Queue
	// A closing queue can hand off a SYN before its drain returns. A tuple
	// lookup can then find a newer pending request. Only this request's own
	// endpoint notification authorizes retiring it from the ingress fence.
	closed := waiter.NewFunctionEntry(waiter.EventHUp, func(waiter.EventMask) { pending.hungUp.Store(true) })
	wq.EventRegister(&closed)
	defer wq.EventUnregister(&closed)
	ep, errTCP := r.CreateEndpoint(&wq)
	if errTCP != nil {
		// TCP already handled the failed handshake. In particular an app RST
		// must not receive another reset from admission during deferred cleanup.
		// Retire before removing pending: the ingress fence may arrive after
		// Complete, while remote.Close still holds up this goroutine's defers.
		discardHandshake()
		return
	}
	abort := func() {
		if closeAdmissionEnabled {
			ticket.Retire()
		}
		ep.Abort()
	}
	closeEndpoint := sync.OnceFunc(ep.Close)
	defer closeEndpoint()
	stopApp := context.AfterFunc(ctx, abort)
	defer stopApp()
	if ctx.Err() != nil {
		// The handshake succeeded; Abort owns the reset, not admission.
		discardHandshake()
		abort()
		return
	}
	rx, tx := ticket.Buffers()
	ep.SocketOptions().SetReceiveBufferSize(int64(rx), true)
	ep.SocketOptions().SetSendBufferSize(int64(tx), true)
	ep.SocketOptions().SetKeepAlive(true)
	// Removal releases this endpoint's slot directly, including timer closes.
	// The callback runs under the endpoint lock: bookkeeping only, no scans
	// or calls back into any endpoint. TIME_WAIT release predates this fix.
	ep.(*gtcp.Endpoint).SetTimeWaitPolicy(ticket.TimeWait, func() {
		if closeAdmissionEnabled {
			ticket.Retire()
		}
		ticket.EndTimeWait()
	})
	c := &connection{id: id, ep: ep, ticket: ticket, last: time.Now(), done: make(chan struct{})}
	f.mu.Lock()
	if f.ctx.Err() != nil || closedState(ep) {
		f.mu.Unlock()
		discardHandshake()
		abort()
		return
	}
	f.connections[id] = c
	owned = false // the shared monitor now owns the reservation
	f.mu.Unlock()
	// Keep the pending entry through endpoint setup. A delayed reopen hook
	// must see either pending or connections, never a gap between them.
	complete(false)
	defer close(c.done)
	app := &onceCloseConn{TCPConn: gonet.NewTCPConn(&wq, ep), close: closeEndpoint, afterCloseWrite: c.releaseAdmission}
	if a, ok := remote.LocalAddr().(*net.TCPAddr); ok {
		ticket.Established(a.AddrPort().Addr())
	} else {
		ticket.Established(netip.Addr{})
	}
	count := func(u, d uint64) { c.up.Add(u); c.down.Add(d); ticket.Add(u, d) }
	if err := Splice(ctx, app, remote, count, abort); err != nil {
		abort()
	}
	app.Close()
	c.releaseAdmission()
	// TCP releases admission once both directions end and payload drains, or
	// on reset/removal. Keep the ticket until removal and relay completion
	// for final byte accounting.
}

// Stop cancels dials and relays. The owner must close the stack before Wait,
// which also unblocks handshakes whose app never sent its final ACK.
func (f *Forwarder) Stop() { f.mu.Lock(); f.cancel(); f.mu.Unlock() }
func (f *Forwarder) Wait() { f.wg.Wait() }

// gonet.Close delegates directly to Endpoint.Close, which requires one call.
// Cancellation, splice errors and normal cleanup share this single owner.
type onceCloseConn struct {
	*gonet.TCPConn
	close           func()
	afterCloseWrite func()
}

func (c *onceCloseConn) Close() error { c.close(); return nil }

func (c *onceCloseConn) CloseWrite() error {
	err := c.TCPConn.CloseWrite()
	if c.afterCloseWrite != nil {
		c.afterCloseWrite()
	}
	return err
}
