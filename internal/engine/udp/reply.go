package udp

import (
	"context"
	"errors"
	"net/netip"
	"sync"

	"github.com/AyoubAchour/net-switch/internal/engine/flowapi"
	"github.com/AyoubAchour/net-switch/internal/engine/packet"
	"github.com/AyoubAchour/net-switch/internal/engine/platform"
)

var errReplyBudget = errors.New("UDP reply byte budget exhausted")

// A bounded cache survives GC under the memory-pressure workload. Storage is
// allocated lazily and is independent of the number of idle UDP sessions.
type udpReadBuffers struct {
	mu    sync.Mutex
	items [64]*[flowapi.UDPReadBuffer]byte
	count int
}

func (p *udpReadBuffers) get() *[flowapi.UDPReadBuffer]byte {
	p.mu.Lock()
	if p.count != 0 {
		p.count--
		b := p.items[p.count]
		p.items[p.count] = nil
		p.mu.Unlock()
		return b
	}
	p.mu.Unlock()
	return new([flowapi.UDPReadBuffer]byte)
}

func (p *udpReadBuffers) put(b *[flowapi.UDPReadBuffer]byte) {
	p.mu.Lock()
	if p.count < len(p.items) {
		p.items[p.count] = b
		p.count++
	}
	p.mu.Unlock()
}

var readBuffers udpReadBuffers

type udpReply struct {
	size    int
	packets [][]byte
	release func()
}

func (s *session) readPacket(ctx context.Context) (udpReply, error) {
	if err := s.socket.WaitReadable(ctx); err != nil {
		return udpReply{}, err
	}
	return s.readAvailable(s.socket.ReadFrom)
}

func (s *session) readAvailable(read func([]byte) (int, netip.AddrPort, error)) (udpReply, error) {
	control := s.n.control
	if !control.ReserveReply(flowapi.UDPReadBuffer) {
		// Consume this datagram without allocating its payload. The mapping
		// survives overload; a one-byte read may report truncation on Windows.
		var discard [1]byte
		if _, _, err := read(discard[:]); errors.Is(err, platform.ErrWouldBlock) {
			return udpReply{}, err
		}
		return udpReply{}, errReplyBudget
	}
	account, _ := control.(interface{ ObserveUDPRead(int) })
	if account != nil {
		account.ObserveUDPRead(flowapi.UDPReadBuffer)
	}
	buf := readBuffers.get()
	defer func() {
		readBuffers.put(buf)
		if account != nil {
			account.ObserveUDPRead(-flowapi.UDPReadBuffer)
		}
		control.ReleaseReply(flowapi.UDPReadBuffer)
	}()
	size, remote, err := read(buf[:])
	if err != nil {
		return udpReply{}, err
	}
	if size < 0 || size > len(buf) {
		return udpReply{}, &platform.TooBig{}
	}
	bytes := packet.UDPReplySize(remote.Addr(), s.source.Addr(), size, s.n.mtu)
	if bytes == 0 {
		return udpReply{}, &platform.TooBig{}
	}
	if !control.ReserveReply(bytes) {
		return udpReply{}, errReplyBudget
	}
	id := s.n.fragmentID.Add(1)
	packets := packet.UDPReply(remote, s.source, buf[:size], s.n.mtu, id)
	// SendBatch takes this lease, including on rejection. Closing the session
	// must not release it while a fragment is still queued or held by a writer.
	return udpReply{size: size, packets: packets, release: func() { control.ReleaseReply(bytes) }}, nil
}
