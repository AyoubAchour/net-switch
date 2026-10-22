// Package udp owns endpoint-independent UDP mappings. No gVisor UDP endpoint
// is ever registered, including for replies or probes.
package udp

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/AyoubAchour/net-switch/internal/engine/flowapi"
	"github.com/AyoubAchour/net-switch/internal/engine/packet"
	"github.com/AyoubAchour/net-switch/internal/engine/platform"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	gu "gvisor.dev/gvisor/pkg/tcpip/transport/udp"
)

const PendingPackets = 64
const PendingBytes = 256 << 10
const IdleTimeout = 5 * time.Minute
const IdentityMaxAge = 2 * time.Second
const RejectLifetime = time.Second
const RejectCacheEntries = 4096
const shards = 32

type datagram struct {
	destination       netip.AddrPort
	payload, original []byte
	df                bool
	bytes             int
}
type session struct {
	workers         sync.WaitGroup
	n               *NAT
	source          netip.AddrPort
	ticket          flowapi.Ticket
	mu              sync.Mutex
	queue           []datagram
	bytes           int
	owner           platform.Owner
	pendingDestroys []string
	destroyOverflow bool
	validated, last time.Time
	active, closed  bool
	rejected        bool
	rejectApp       string
	rejectedAt      time.Time
	socket          platform.UDPConn
	wake            chan struct{}
	done            chan struct{}
	cancel          context.CancelFunc
	ready           atomic.Pointer[readySession]
}
type shard struct {
	sync.Mutex
	m        map[netip.AddrPort]*session
	negative map[netip.AddrPort]refusedSession
}
type refusedSession struct {
	owner platform.Owner
	at    time.Time
}
type NAT struct {
	ctx                                                              context.Context
	cancel                                                           context.CancelFunc
	control                                                          flowapi.Controller
	owners                                                           platform.OwnerLookup
	identities                                                       platform.UDPIdentity
	dialer                                                           platform.LineDialer
	out                                                              flowapi.DatagramOutput
	fragmentID                                                       atomic.Uint32
	now                                                              func() time.Time
	mtu                                                              int
	table                                                            [shards]shard
	closed                                                           atomic.Bool
	wg                                                               sync.WaitGroup
	reconcileMu                                                      sync.Mutex
	refresh                                                          chan struct{}
	io                                                               *udpWorkers
	Invalid, Dropped, Rejected, IdentityErrors, Oversize, ReadErrors atomic.Uint64
	PeakQueuePackets, PeakQueueBytes                                 atomic.Uint64
	OpenFailed                                                       atomic.Uint64
	GenerationMissing                                                atomic.Uint64
}

func New(ctx context.Context, s *stack.Stack, c flowapi.Controller, o platform.OwnerLookup, i platform.UDPIdentity, d platform.LineDialer, out flowapi.DatagramOutput, mtu int) *NAT {
	ctx, cancel := context.WithCancel(ctx)
	n := &NAT{ctx: ctx, cancel: cancel, control: c, owners: o, identities: i, dialer: d, out: out, now: time.Now, mtu: mtu, refresh: make(chan struct{}, 1)}
	n.io = newUDPWorkers()
	var seed [4]byte
	rand.Read(seed[:])
	n.fragmentID.Store(binary.NativeEndian.Uint32(seed[:]))
	for j := range n.table {
		n.table[j].m = make(map[netip.AddrPort]*session)
	}
	if s != nil {
		s.SetTransportProtocolHandler(gu.ProtocolNumber, n.Handle)
	}
	n.wg.Go(n.maintenance)
	return n
}

func (n *NAT) bucket(key netip.AddrPort) *shard { return &n.table[int(key.Port())%shards] }

func (n *NAT) Handle(id stack.TransportEndpointID, p *stack.PacketBuffer) bool {
	h := header.UDP(p.TransportHeader().Slice())
	if len(h) < 8 {
		n.Invalid.Add(1)
		return true
	}
	length, csum := header.UDPValid(h, p.Data().Checksum, uint16(p.Data().Size()), p.NetworkProtocolNumber, id.RemoteAddress, id.LocalAddress, false)
	if !length || !csum || (p.NetworkProtocolNumber == header.IPv6ProtocolNumber && h.Checksum() == 0) {
		n.Invalid.Add(1)
		return true
	}
	src, _ := netip.AddrFromSlice(id.RemoteAddress.AsSlice())
	dst, _ := netip.AddrFromSlice(id.LocalAddress.AsSlice())
	source, destination := netip.AddrPortFrom(src, id.RemotePort), netip.AddrPortFrom(dst, id.LocalPort)
	// UDPValid allows trailing IP padding. Keep only the UDP-declared data.
	dataSize := int(h.Length()) - 8
	if dataSize < 0 || dataSize > p.Data().Size() {
		n.Invalid.Add(1)
		return true
	}
	network := p.NetworkHeader().Slice()
	headerBytes := len(network) + len(h)
	originalSize := headerBytes + p.Data().Size()
	n.receive(source, destination, dataSize+originalSize, func() ([]byte, []byte, bool) {
		payload := p.Data().AsRange().Capped(dataSize).ToSlice()
		// ICMP must quote the triggering headers, including the IPv4 ID,
		// options/flags and the original UDP checksum (which may be zero on
		// IPv4). Retain IP padding too, so the original length stays valid.
		original := make([]byte, originalSize)
		copy(original, network)
		copy(original[len(network):], h)
		writer := tcpip.SliceWriter(original[headerBytes:])
		_, _ = p.Data().ReadTo(&writer, true) // destination has exactly Data().Size() bytes
		df := false
		if src.Is4() {
			ip := header.IPv4(network)
			df = ip.Flags()&header.IPv4FlagDontFragment != 0
			// Reassembly updates total length and fragment flags in gVisor's
			// header. Repair its checksum; an ordinary packet stays identical.
			original[10], original[11] = 0, 0
			binary.BigEndian.PutUint16(original[10:], ^packet.Sum(original[:len(network)], 0))
		} else {
			// IPv6 has no DF bit. An unfragmented packet must learn a smaller
			// path through PTB; once the host sends fragments, preserve that
			// decision on our real socket after gVisor reassembles them.
			df = !ipv6Fragmented(p.NetworkHeader().Slice())
		}
		return payload, original, df
	})
	return true
}

func ipv6Fragmented(ip []byte) bool {
	if len(ip) < 40 {
		return false
	}
	next, offset := ip[6], 40
	for offset+2 <= len(ip) {
		if next == 44 {
			return true
		}
		var size int
		switch next {
		case 0, 43, 60:
			size = (int(ip[offset+1]) + 1) * 8
		case 51:
			size = (int(ip[offset+1]) + 2) * 4
		default:
			return false
		}
		if size < 8 || offset+size > len(ip) {
			return false
		}
		next = ip[offset]
		offset += size
	}
	return false
}

func (n *NAT) receive(source, destination netip.AddrPort, ownedBytes int, copyPacket func() ([]byte, []byte, bool)) {
	b := n.bucket(source)
	b.Lock()
	if n.closed.Load() {
		b.Unlock()
		return
	}
	s := b.m[source]
	created := false
	if s == nil {
		if denied, ok := b.negative[source]; ok {
			if n.now().Sub(denied.at) < RejectLifetime {
				b.Unlock()
				if n.control.AllowReject(denied.owner.AppID) {
					_, raw, _ := copyPacket()
					n.out.Send(packet.Unreachable(raw, 0))
				} else {
					n.Dropped.Add(1)
				}
				return
			}
			delete(b.negative, source)
		}
		t, err := n.control.Begin("udp", platform.Tuple{Source: source, Destination: destination})
		if err != nil {
			b.Unlock()
			n.Rejected.Add(1)
			if n.control.AllowReject("") {
				_, raw, _ := copyPacket()
				n.out.Send(packet.Unreachable(raw, 0))
			} else {
				n.Dropped.Add(1)
			}
			return
		}
		s = &session{n: n, source: source, ticket: t, last: n.now(), wake: make(chan struct{}, 1), done: make(chan struct{})}
		n.wg.Add(1)
		b.m[source] = s
		created = true
	}
	s.mu.Lock()
	b.Unlock()
	if s.rejected {
		app := s.rejectApp
		s.mu.Unlock()
		if n.control.AllowReject(app) {
			_, raw, _ := copyPacket()
			n.out.Send(packet.Unreachable(raw, 0))
		} else {
			n.Dropped.Add(1)
		}
		return
	}
	// Reserve both exact owned copies. IPv4 options and IPv6 extensions make
	// the quotation's header larger than the old fixed 48-byte allowance.
	bytes := ownedBytes
	if s.closed || len(s.queue) >= PendingPackets || s.bytes+bytes > PendingBytes || !n.control.ReservePending(bytes) {
		s.mu.Unlock()
		n.Dropped.Add(1)
		if created {
			s.close()
			s.ticket.Close()
			n.wg.Done()
		}
		return
	}
	payload, raw, df := copyPacket()
	s.queue = append(s.queue, datagram{destination: destination, payload: payload, original: raw, df: df, bytes: bytes})
	s.bytes += bytes
	for old := n.PeakQueuePackets.Load(); uint64(len(s.queue)) > old && !n.PeakQueuePackets.CompareAndSwap(old, uint64(len(s.queue))); old = n.PeakQueuePackets.Load() {
	}
	for old := n.PeakQueueBytes.Load(); uint64(s.bytes) > old && !n.PeakQueueBytes.CompareAndSwap(old, uint64(s.bytes)); old = n.PeakQueueBytes.Load() {
	}
	s.mu.Unlock()
	if created {
		go s.run()
	}
	if r := s.ready.Load(); r != nil {
		r.notify()
		return
	}
	select {
	case s.wake <- struct{}{}:
	default:
	}
}

func (s *session) close() {
	n := s.n
	b := n.bucket(s.source)
	b.Lock()
	if b.m[s.source] == s {
		delete(b.m, s.source)
	}
	s.mu.Lock()
	b.Unlock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	s.closed = true
	close(s.done)
	socket, cancel, ready := s.socket, s.cancel, s.ready.Load()
	bytes := s.bytes
	s.bytes = 0
	s.queue = nil
	s.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	if ready != nil {
		ready.notify()
	} else if socket != nil {
		socket.Close()
	}
	n.control.ReleasePending(bytes)
}

func (s *session) run() {
	n := s.n
	handedOff := false
	// Socket completion counters must finish before the final totals fold.
	defer func() {
		if !handedOff {
			s.close()
			s.workers.Wait()
			s.ticket.Close()
			n.wg.Done()
		}
	}()
	ctx, cancel := context.WithCancel(n.ctx)
	defer cancel()
	s.mu.Lock()
	s.cancel = cancel
	closed := s.closed
	s.mu.Unlock()
	if closed {
		return
	}
	s.ticket.SetCancel(cancel)
	lookup, cl := context.WithTimeout(ctx, 50*time.Millisecond)
	lookupStart := time.Now()
	var owner platform.Owner
	var err error
	if owners, ok := n.owners.(platform.DatagramOwnerLookup); ok {
		s.mu.Lock()
		var destination netip.AddrPort
		if len(s.queue) > 0 {
			destination = s.queue[0].destination
		}
		s.mu.Unlock()
		if !destination.IsValid() {
			cl()
			return
		}
		owner, err = owners.UDPFor(lookup, platform.Tuple{Source: s.source, Destination: destination})
	} else {
		owner, err = n.owners.UDP(lookup, s.source)
	}
	if observer, ok := n.control.(interface {
		Lookup(time.Duration, error, platform.Owner)
	}); ok {
		observer.Lookup(time.Since(lookupStart), err, owner)
	}
	cl()
	if err != nil {
		// Attribution may be unknown while the kernel socket cookie is known.
		// Keep that cookie so unknown-owner sessions can still be validated.
		owner = platform.Owner{Generation: owner.Generation}
	}
	s.mu.Lock()
	s.owner = owner
	destroyed := false
	for _, generation := range s.pendingDestroys {
		if generation == owner.Generation {
			destroyed = true
		}
	}
	verify := s.destroyOverflow
	s.pendingDestroys = nil
	s.mu.Unlock()
	if destroyed {
		return
	}
	if verify {
		if n.identities == nil {
			n.IdentityErrors.Add(1)
			return
		}
		live, err := n.identities.Snapshot(ctx, []netip.AddrPort{s.source})
		if err != nil || !same(live[s.source], owner) {
			n.IdentityErrors.Add(1)
			return
		}
	}
	// No generation means we cannot prove this socket is still the same one.
	if owner.Generation == "" {
		n.IdentityErrors.Add(1)
		n.GenerationMissing.Add(1)
		if reporter, ok := n.control.(interface{ Emit(flowapi.Event) }); ok {
			reporter.Emit(flowapi.Event{Type: "log", Message: fmt.Sprintf("UDP setup has no socket generation: source=%s lookup=%v", s.source, err)})
		}
		s.refuseSetup(owner.AppID)
		return
	}
	decision, err := s.ticket.Resolve(owner)
	if err != nil {
		n.Rejected.Add(1)
		s.rejectPending(owner.AppID)
		return
	}
	var socket platform.UDPConn
	if dialer, ok := n.dialer.(platform.DestinationDialer); ok {
		s.mu.Lock()
		var destination netip.AddrPort
		if len(s.queue) > 0 {
			destination = s.queue[0].destination
		}
		s.mu.Unlock()
		if !destination.IsValid() {
			return
		}
		socket, err = dialer.OpenUDPTo(ctx, decision.Line, destination)
	} else if dialer, ok := n.dialer.(platform.FlowDialer); ok {
		flow := platform.FlowIdentity{Owner: owner, Source: s.source}
		s.mu.Lock()
		if len(s.queue) > 0 {
			flow.Destination = s.queue[0].destination
		}
		s.mu.Unlock()
		socket, err = dialer.OpenFlowUDP(ctx, decision.Line, s.source.Addr().Is6(), flow)
	} else {
		socket, err = n.dialer.OpenUDP(ctx, decision.Line, s.source.Addr().Is6())
	}
	if err != nil {
		n.OpenFailed.Add(1)
		if observer, ok := n.control.(interface{ LineError(string, error) }); ok && ctx.Err() == nil {
			observer.LineError(decision.Line, err)
		}
		s.refuseSetup(owner.AppID)
		return
	}
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		socket.Close()
		return
	}
	s.socket = socket
	s.owner = owner
	s.validated = n.now()
	s.active = true
	s.mu.Unlock()
	s.ticket.Established(socket.LocalAddr().Addr())
	if q, ok := socket.(platform.UDPErrorHandler); ok {
		q.SetErrorHandler(s.errorReply)
	}
	if socket, ok := socket.(platform.ReadyUDP); ok {
		handedOff = s.startReady(socket)
		return
	}
	s.workers.Go(func() { s.read(ctx) })
	if q, ok := socket.(platform.UDPErrorQueue); ok {
		if _, inline := socket.(platform.UDPErrorHandler); !inline {
			s.workers.Go(func() { s.readErrors(ctx, q) })
		}
	}
	for {
		select {
		case <-ctx.Done():
			return
		case <-s.done:
			return
		case <-s.wake:
		}
		for {
			s.mu.Lock()
			if s.closed || len(s.queue) == 0 {
				s.mu.Unlock()
				break
			}
			d := s.queue[0]
			s.queue[0] = datagram{}
			s.queue = s.queue[1:]
			s.bytes -= d.bytes
			fresh := n.now().Sub(s.validated) < IdentityMaxAge
			s.mu.Unlock()
			if fresh {
				written, err := socket.WriteTo(d.payload, d.destination, d.df)
				if err == nil {
					s.ticket.Add(uint64(written), 0)
					s.mu.Lock()
					s.last = n.now()
					s.mu.Unlock()
				} else if errors.Is(err, platform.ErrDatagramDropped) {
					n.Dropped.Add(1)
				} else if n.control.AllowReject(owner.AppID) {
					var big *platform.TooBig
					if errors.As(err, &big) {
						n.out.Send(packet.Unreachable(d.original, big.MTU))
					} else {
						n.out.Send(packet.Unreachable(d.original, 0))
					}
				}
			} else {
				n.Dropped.Add(1)
			}
			n.control.ReleasePending(d.bytes)
		}
	}
}

func (s *session) rejectPending(app string) {
	// Failed setups must disappear from counts and pagination before any
	// refusal is observable. Suppression has its own bounded, timer-free cache.
	s.ticket.Retire()
	b := s.n.bucket(s.source)
	b.Lock()
	s.mu.Lock()
	if !s.closed && b.m[s.source] == s {
		if b.negative == nil {
			b.negative = make(map[netip.AddrPort]refusedSession)
		}
		if len(b.negative) >= RejectCacheEntries/shards {
			var oldest netip.AddrPort
			var at time.Time
			for key, entry := range b.negative {
				if !oldest.IsValid() || entry.at.Before(at) {
					oldest, at = key, entry.at
				}
			}
			delete(b.negative, oldest)
		}
		b.negative[s.source] = refusedSession{owner: s.owner, at: s.n.now()}
	}
	b.Unlock()
	defer s.mu.Unlock()
	// A packet arriving after this flush must also receive a rejection, even
	// if close has not yet removed the session from its shard.
	s.rejected = true
	s.rejectApp = app
	s.rejectedAt = s.n.now()
	for _, d := range s.queue {
		if s.n.control.AllowReject(app) {
			s.n.out.Send(packet.Unreachable(d.original, 0))
		} else {
			s.n.Dropped.Add(1)
		}
	}
	s.n.control.ReleasePending(s.bytes)
	s.bytes = 0
	s.queue = nil
}

func (s *session) refuseSetup(app string) {
	s.n.Rejected.Add(1)
	if ticket, ok := s.ticket.(interface{ RefuseSetup() }); ok {
		ticket.RefuseSetup()
	}
	s.rejectPending(app)
}

func (s *session) read(ctx context.Context) {
	n := s.n
	defer s.close()
	for {
		reply, err := s.readPacket(ctx)
		if err != nil {
			if errors.Is(err, net.ErrClosed) || ctx.Err() != nil {
				return
			}
			if errors.Is(err, errReplyBudget) {
				n.Dropped.Add(1)
			} else if platform.IsTooBig(err) {
				n.Oversize.Add(1)
			} else {
				n.ReadErrors.Add(1)
			}
			// A permanently failing adapter must not turn this into a busy loop.
			if !waitReadRetry(ctx) {
				return
			}
			continue
		}
		s.mu.Lock()
		fresh := !s.closed && n.now().Sub(s.validated) < IdentityMaxAge
		s.mu.Unlock()
		if !fresh {
			reply.release()
			n.Dropped.Add(1)
			continue
		}
		if n.out.SendBatch(reply.packets, reply.release) {
			s.ticket.Add(0, uint64(reply.size))
			s.mu.Lock()
			s.last = n.now()
			s.mu.Unlock()
		} else {
			n.Dropped.Add(1)
		}
		if ctx.Err() != nil {
			return
		}
	}
}

func (s *session) readErrors(ctx context.Context, q platform.UDPErrorQueue) {
	for {
		e, err := q.ReadError(ctx)
		if err != nil {
			return
		}
		s.errorReply(e)
	}
}

func (s *session) errorReply(e platform.DatagramError) {
	s.mu.Lock()
	fresh := !s.closed && s.n.now().Sub(s.validated) < IdentityMaxAge
	app := s.owner.AppID
	s.mu.Unlock()
	if fresh && s.n.control.AllowReject(app) {
		s.n.out.Send(packet.Unreachable(packet.UDP(s.source, e.Destination, e.Payload), e.MTU))
	}
}
