//go:build windows

package wintun

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"runtime"
	"sync/atomic"
	"unsafe"

	"github.com/AyoubAchour/net-switch/internal/engine/packet"
	"golang.org/x/sys/windows"
	"gvisor.dev/gvisor/pkg/tcpip/checksum"
)

const (
	MaxPacketSize      = 65535
	MinCapacity        = 128 << 10
	MaxCapacity        = 64 << 20
	ringHeader         = 12
	ringSlack          = 65536
	registerRingsIOCTL = uint32(51820<<16 | 3<<14 | 0x970<<2)
)

var ErrCorrupt = errors.New("Wintun ring corruption")
var ErrDisconnected = errors.New("Wintun adapter disconnected")

func corrupt(r ring, direction, reason string, head, tail uint32) error {
	var size uint32
	if head < r.capacity {
		size = binary.LittleEndian.Uint32(r.data()[head : head+4])
	}
	return fmt.Errorf("%w: %s %s (head=%d tail=%d size=%d capacity=%d)", ErrCorrupt, direction, reason, head, tail, size, r.capacity)
}

func validCapacity(n uint32) bool { return n >= MinCapacity && n <= MaxCapacity && n&(n-1) == 0 }
func aligned(n uint32) uint32     { return (n + 3) &^ 3 }

// entry checks all arithmetic before slicing. A wrapping packet is contiguous
// in the extra 65536 bytes; only the next cursor wraps, not the packet bytes.
func entry(data []byte, capacity, head, tail uint32) ([]byte, uint32, error) {
	if !validCapacity(capacity) || uint64(len(data)) < uint64(capacity)+ringSlack {
		return nil, head, ErrCorrupt
	}
	if head >= capacity || tail >= capacity || (head|tail)&3 != 0 {
		return nil, head, ErrCorrupt
	}
	available := (tail - head) & (capacity - 1)
	if available == 0 {
		return nil, head, io.EOF
	}
	size := binary.LittleEndian.Uint32(data[head : head+4])
	if size == 0 || size > MaxPacketSize || aligned(size+4) > available {
		return nil, head, ErrCorrupt
	}
	return data[head+4 : head+4+size], (head + aligned(size+4)) & (capacity - 1), nil
}

type ring struct {
	bytes    []byte
	capacity uint32
}

func (r ring) word(offset int) *uint32    { return (*uint32)(unsafe.Pointer(&r.bytes[offset])) }
func (r ring) load(offset int) uint32     { return atomic.LoadUint32(r.word(offset)) }
func (r ring) store(offset int, n uint32) { atomic.StoreUint32(r.word(offset), n) }
func (r ring) data() []byte               { return r.bytes[ringHeader:] }

// Go atomics are sequentially consistent (stronger than the ABI's acquire and
// release requirements), including on ARM64. The backing arrays are pinned
// until CloseHandle has synchronously unregistered the driver's MDLs.
type rings struct {
	send, receive                 ring
	pin                           runtime.Pinner
	device, readEvent, writeEvent windows.Handle
	head, tail                    uint32
}

type ringRegistration struct {
	Size  uint32
	Ring  *byte
	Event windows.Handle
}
type registration struct{ Send, Receive ringRegistration }

func openRings(path string, capacity uint32) (_ *rings, err error) {
	if !validCapacity(capacity) {
		return nil, fmt.Errorf("invalid ring capacity %d", capacity)
	}
	r := &rings{}
	defer func() {
		if err != nil {
			err = errors.Join(err, r.close())
		}
	}()
	size := int(capacity) + ringHeader + ringSlack
	buffer := make([]byte, size*2)
	r.pin.Pin(&buffer[0])
	r.send = ring{buffer[:size], capacity}
	r.receive = ring{buffer[size:], capacity}
	r.readEvent, err = windows.CreateEvent(nil, 0, 0, nil)
	if err != nil {
		return nil, err
	}
	r.writeEvent, err = windows.CreateEvent(nil, 0, 0, nil)
	if err != nil {
		return nil, err
	}
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	r.device, err = windows.CreateFile(p, windows.GENERIC_READ|windows.GENERIC_WRITE, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil, windows.OPEN_EXISTING, 0, 0)
	if err != nil {
		r.device = 0
		return nil, err
	}
	desc := registration{
		Send:    ringRegistration{uint32(size), &r.send.bytes[0], r.readEvent},
		Receive: ringRegistration{uint32(size), &r.receive.bytes[0], r.writeEvent},
	}
	var returned uint32
	err = windows.DeviceIoControl(r.device, registerRingsIOCTL, (*byte)(unsafe.Pointer(&desc)), uint32(unsafe.Sizeof(desc)), nil, 0, &returned, nil)
	if err != nil {
		return nil, fmt.Errorf("register Wintun rings: %w", err)
	}
	return r, nil
}

func (r *rings) close() error {
	var err error
	// The device must go first: this sets Disconnected and waits for the receive
	// thread and outstanding NDIS packets before unlocking either ring.
	if r.device != 0 {
		if e := windows.CloseHandle(r.device); e != nil {
			return e
		}
		r.device = 0
	}
	for _, h := range []*windows.Handle{&r.readEvent, &r.writeEvent} {
		if *h != 0 {
			err = errors.Join(err, windows.CloseHandle(*h))
			*h = 0
		}
	}
	r.pin.Unpin()
	r.send.bytes, r.receive.bytes = nil, nil
	return err
}

func (r *rings) read(buffers [][]byte, sizes []int) (int, error) {
	tail := r.send.load(4)
	if tail == ^uint32(0) {
		return 0, ErrDisconnected
	}
	if r.send.load(0) != r.head {
		return 0, corrupt(r.send, "Send", "head changed", r.send.load(0), tail)
	}
	head := r.head
	for i := range buffers {
		packet, next, err := entry(r.send.data(), r.send.capacity, head, tail)
		if err == io.EOF {
			return i, nil
		}
		if err != nil {
			return i, corrupt(r.send, "Send", "invalid entry", head, tail)
		}
		if len(buffers[i]) < len(packet) {
			return i, io.ErrShortBuffer
		}
		copy(buffers[i], packet)
		// The driver's parallel-producer bug can overwrite occupied data.
		// Check the private copy before publishing Head or delivering anything.
		if binary.LittleEndian.Uint32(r.send.data()[head:head+4]) != uint32(len(packet)) || !validIP(buffers[i][:len(packet)]) {
			return i, corrupt(r.send, "Send", "packet changed or failed validation", head, tail)
		}
		sizes[i] = len(packet)
		head = next
		r.head = head
		r.send.store(0, head)
	}
	return len(buffers), nil
}

// Checksums catch damaged bodies whose ring length still looks plausible.
// Fragments go to the engine's reassembly path without a transport checksum
// check. A ring protocol cannot detect corruption that is itself a valid packet.
func validIP(p []byte) bool {
	if len(p) == 0 {
		return false
	}
	var src, dst netip.Addr
	var protocol byte
	var payload []byte
	switch p[0] >> 4 {
	case 4:
		if len(p) < 20 {
			return false
		}
		n := int(p[0]&15) * 4
		if n < 20 || n > len(p) || int(binary.BigEndian.Uint16(p[2:4])) != len(p) {
			return false
		}
		if binary.BigEndian.Uint16(p[6:8])&0x3fff != 0 {
			return true
		}
		if checksum.Checksum(p[:n], 0) != 65535 {
			return false
		}
		src = netip.AddrFrom4([4]byte(p[12:16]))
		dst = netip.AddrFrom4([4]byte(p[16:20]))
		protocol, payload = p[9], p[n:]
	case 6:
		if len(p) < 40 || int(binary.BigEndian.Uint16(p[4:6]))+40 != len(p) {
			return false
		}
		src = netip.AddrFrom16([16]byte(p[8:24]))
		dst = netip.AddrFrom16([16]byte(p[24:40]))
		protocol, payload = p[6], p[40:]
		for protocol == 0 || protocol == 43 || protocol == 60 {
			if len(payload) < 8 {
				return false
			}
			n := (int(payload[1]) + 1) * 8
			if n > len(payload) {
				return false
			}
			protocol, payload = payload[0], payload[n:]
		}
		if protocol == 44 {
			return len(payload) >= 8
		}
	default:
		return false
	}
	switch protocol {
	case 6:
		if len(payload) < 20 || int(payload[12]>>4)*4 < 20 || int(payload[12]>>4)*4 > len(payload) {
			return false
		}
	case 17:
		if len(payload) < 8 || int(binary.BigEndian.Uint16(payload[4:6])) != len(payload) {
			return false
		}
		if src.Is4() && binary.BigEndian.Uint16(payload[6:8]) == 0 {
			return true
		}
	default:
		return true // ICMP, ESP and other protocols are checked by the stack.
	}
	return checksum.Checksum(payload, packet.Sum(nil, packet.Pseudo(src, dst, protocol, len(payload)))) == 65535
}

func (r *rings) write(packets [][]byte) (written, dropped int, err error) {
	head := r.receive.load(0)
	if head == ^uint32(0) {
		return 0, len(packets), ErrDisconnected
	}
	capacity := r.receive.capacity
	if head >= capacity || head&3 != 0 || r.receive.load(4) != r.tail {
		return 0, len(packets), corrupt(r.receive, "Receive", "invalid cursor", head, r.receive.load(4))
	}
	tail := r.tail
	for _, p := range packets {
		if len(p) == 0 || len(p) > MaxPacketSize {
			dropped++
			continue
		}
		size := aligned(uint32(len(p)) + 4)
		if size > (head-tail-4)&(capacity-1) {
			dropped++
			continue
		}
		data := r.receive.data()
		binary.LittleEndian.PutUint32(data[tail:tail+4], uint32(len(p)))
		copy(data[tail+4:], p)
		tail = (tail + size) & (capacity - 1)
		written++
	}
	if written != 0 {
		r.tail = tail
		r.receive.store(4, tail)
		// Never consult Receive.Alertable. An auto-reset event retains this
		// signal until the driver waits, including the store/load race in 0.14.1.
		err = windows.SetEvent(r.writeEvent)
	}
	return
}
