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
	pending                       map[stack.TransportEndpointID]flowapi.Ticket
	wg                            sync.WaitGroup
	forwarder                     *gtcp.Forwarder
	control                       flowapi.Controller
	owners                        platform.OwnerLookup
	dialer                        platform.LineDialer
	out                           flowapi.Output
	Rejected, Invalid, DialFailed atomic.Uint64
}

func New(ctx context.Context, s *stack.Stack, inFlight int, control flowapi.Controller, owners platform.OwnerLookup, dialer platform.LineDialer, out flowapi.Output) *Forwarder {
	ctx, cancel := context.WithCancel(ctx)
	f := &Forwarder{ctx: ctx, cancel: cancel, pending: make(map[stack.TransportEndpointID]flowapi.Ticket), control: control, owners: owners, dialer: dialer, out: out}
	f.forwarder = gtcp.NewForwarder(s, MinimumBuffer, 2*inFlight, f.open)
	s.SetTransportProtocolHandler(gtcp.ProtocolNumber, f.Handle)
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
	if _, ok := f.pending[id]; ok {
		return true
	}
	if f.ctx.Err() != nil {
		return true
	}
	t := tuple(id)
	ticket, err := f.control.Begin("tcp", t)
	if err != nil {
		f.Rejected.Add(1)
		if f.control.AllowReject("") {
			f.out.Send(packet.Reset(t.Destination, t.Source, 0, h.SequenceNumber()+1, true))
		}
		return true
	}
	f.pending[id] = ticket
	f.wg.Add(1)
	if !f.forwarder.HandlePacket(id, p) {
		delete(f.pending, id)
		ticket.Close()
		f.wg.Done()
	}
	return true
}

func (f *Forwarder) open(r *gtcp.ForwarderRequest) {
	defer f.wg.Done()
	id := r.ID()
	f.mu.Lock()
	ticket := f.pending[id]
	f.mu.Unlock()
	defer ticket.Close()
	// Complete exactly once, on every return path. Retain the deduplication
	// entry until Complete has removed gVisor's own in-flight entry.
	completed := false
	complete := func(reset bool) {
		if completed {
			return
		}
		completed = true
		r.Complete(reset)
		f.mu.Lock()
		delete(f.pending, id)
		f.mu.Unlock()
	}
	owner := platform.Owner{}
	defer func() {
		if !completed {
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
		return
	}
	defer remote.Close()
	stopRemote := context.AfterFunc(ctx, func() { remote.Close() })
	defer stopRemote()
	if ctx.Err() != nil {
		return
	}
	var wq waiter.Queue
	ep, errTCP := r.CreateEndpoint(&wq)
	if errTCP != nil {
		return
	}
	complete(false)
	defer ep.Close()
	stopApp := context.AfterFunc(ctx, ep.Abort)
	defer stopApp()
	if ctx.Err() != nil {
		ep.Abort()
		return
	}
	rx, tx := ticket.Buffers()
	ep.SocketOptions().SetReceiveBufferSize(int64(rx), true)
	ep.SocketOptions().SetSendBufferSize(int64(tx), true)
	ep.SocketOptions().SetKeepAlive(true)
	app := gonet.NewTCPConn(&wq, ep)
	defer app.Close()
	if a, ok := remote.LocalAddr().(*net.TCPAddr); ok {
		ticket.Established(a.AddrPort().Addr())
	} else {
		ticket.Established(netip.Addr{})
	}
	if err := Splice(ctx, app, remote, ticket.Add, ep.Abort); err != nil {
		ep.Abort()
	}
}

// Stop cancels dials and relays. The owner must close the stack before Wait,
// which also unblocks handshakes whose app never sent its final ACK.
func (f *Forwarder) Stop() { f.mu.Lock(); f.cancel(); f.mu.Unlock() }
func (f *Forwarder) Wait() { f.wg.Wait() }
