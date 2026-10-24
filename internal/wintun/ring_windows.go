//go:build windows

package wintun

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/AyoubAchour/net-switch/internal/engine/packet"
	"github.com/AyoubAchour/net-switch/internal/winclock"
	"github.com/AyoubAchour/net-switch/internal/winhandle"
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
var ErrAdapterRemoved = errors.New("Wintun adapter removed")

// ErrRegistrarExited reports that the process owning the registration ended.
// The driver then releases the rings, so the session is lost exactly as on
// adapter removal; callers see it joined with ErrAdapterRemoved.
var ErrRegistrarExited = fmt.Errorf("Wintun registrar exited: %w", ErrDisconnected)
var errRegistrationHeld = errors.New("Wintun registrar ended without the driver's release markers")
var errRingsRetained = errors.New("Wintun teardown incomplete; ring memory retained until process exit")

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
// release requirements), including on ARM64. Both rings live in one unnamed
// pagefile-backed section. The engine maps one view; the registrar maps its
// own view of the same pages and registers that view with the driver.
type rings struct {
	send, receive           ring
	view                    uintptr // this process's mapped view; 0 once released or retained
	section                 winhandle.Owner
	readEvent, writeEvent   windows.Handle
	readOwner, writeOwner   winhandle.Owner
	owner                   ringOwner // nil for synthetic fixtures without a driver
	closed                  bool
	ownerExitedFirst        bool // set by end(): the owner ended before we requested a stop
	head, tail              uint32
	placeholders, oversized uint64 // protected by the session's read lock
	closeProfile            CloseDetails
}

// ringOwner ends the driver registration. Production uses the registrar
// process; the in-process comparison owner exists only in test files.
type ringOwner interface {
	// exited is signalled when the registration owner itself ends, or 0.
	exited() windows.Handle
	// end returns retain=true when this process's view must stay mapped.
	end(r *rings, closeHandle func(windows.Handle) error) (retain bool, err error)
}

// DeviceNanos is the registration owner's retirement (for the registrar:
// stop request, process exit and handle closes). DriverWaitNanos waits for
// both release markers afterwards.
type CloseDetails struct {
	QueueNanos, ReadLockNanos, StateLockNanos              uint64
	DeviceNanos, DriverWaitNanos, EventsNanos, MemoryNanos uint64
}

type ringRegistration struct {
	Size  uint32
	Ring  *byte
	Event windows.Handle
}
type registration struct{ Send, Receive ringRegistration }

func ringBytes(capacity uint32) int { return int(capacity) + ringHeader + ringSlack }

// viewBytes is the exact size of both rings, as mapped by each process.
func viewBytes(capacity uint32) int { return 2 * ringBytes(capacity) }

func mappedSlice(address uintptr, size int) []byte {
	// A mapped view is outside the Go heap. Reinterpret that native address
	// without Go pointer arithmetic (also valid under checkptr).
	pointer := *(*unsafe.Pointer)(unsafe.Pointer(&address))
	return unsafe.Slice((*byte)(pointer), size)
}

// allocateRings creates the unnamed section and this process's view. Synthetic
// fixtures use the same memory as production sessions.
func allocateRings(capacity uint32) (*rings, error) {
	if !validCapacity(capacity) {
		return nil, fmt.Errorf("invalid ring capacity %d", capacity)
	}
	size := ringBytes(capacity)
	total := uint64(viewBytes(capacity))
	h, err := windows.CreateFileMapping(windows.InvalidHandle, nil, windows.PAGE_READWRITE, uint32(total>>32), uint32(total), nil)
	if err != nil {
		return nil, fmt.Errorf("create Wintun ring section: %w", err)
	}
	section := winhandle.Open(h, "Wintun ring section open")
	address, err := windows.MapViewOfFile(section.Handle("Wintun ring section map"), windows.FILE_MAP_READ|windows.FILE_MAP_WRITE, 0, 0, uintptr(total))
	if err != nil {
		return nil, errors.Join(fmt.Errorf("map Wintun ring section: %w", err), section.HandleClose("Wintun ring section map failure close"))
	}
	buffer := mappedSlice(address, int(total))
	return &rings{view: address, section: section, send: ring{buffer[:size], capacity}, receive: ring{buffer[size:], capacity}}, nil
}

// openRings returns registered rings. The registration's device handle exists
// only in the registrar process; see registrar_windows.go.
func openRings(path string, capacity uint32) (_ *rings, err error) {
	r, err := allocateRings(capacity)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			err = errors.Join(err, r.close())
		}
	}()
	if err = r.createEvents(); err != nil {
		return nil, err
	}
	g, err := startRegistrar(path, r)
	if err != nil {
		return nil, err
	}
	r.owner = g
	return r, nil
}

func (r *rings) createEvents() error {
	h, err := windows.CreateEvent(nil, 0, 0, nil)
	if err != nil {
		return err
	}
	r.readEvent, r.readOwner = h, winhandle.Open(h, "Wintun read event open")
	h, err = windows.CreateEvent(nil, 0, 0, nil)
	if err != nil {
		return err
	}
	r.writeEvent, r.writeOwner = h, winhandle.Open(h, "Wintun write event open")
	return nil
}

func (r *rings) close() error {
	return r.closeWith(windows.CloseHandle)
}

// released reports both driver release markers: Receive.Head, then Send.Tail.
func (r *rings) released() bool {
	return r.send.load(4) == ^uint32(0) && r.receive.load(0) == ^uint32(0)
}

// disconnected reports either marker, as write and read do. In 0.14.1 the
// receive thread writes Receive.Head as it ends (on unregistration, or after
// rejecting a damaged Receive ring), and unregistration then writes Send.Tail.
func (r *rings) disconnected() bool {
	return r.receive.load(0) == ^uint32(0) || r.send.load(4) == ^uint32(0)
}

func (r *rings) exited() windows.Handle {
	if r.owner == nil {
		return 0
	}
	return r.owner.exited()
}

func (r *rings) readHandle() windows.Handle {
	if r.readOwner.IsZero() {
		return r.readEvent // Synthetic ring fault-injection fixtures.
	}
	return r.readOwner.Handle("Wintun read event")
}

func (r *rings) writeHandle() windows.Handle {
	if r.writeOwner.IsZero() {
		return r.writeEvent // Synthetic ring fault-injection fixtures.
	}
	return r.writeOwner.Handle("Wintun write event")
}

func (r *rings) awaitRelease() bool {
	deadline := winclock.Now() + 250*time.Millisecond
	for !r.released() {
		if winclock.Now() >= deadline {
			return false
		}
		winclock.System.WaitDone(nil, time.Millisecond)
	}
	return true
}

// closeWith is also the fault-injection boundary for failed CloseHandle calls.
// A close attempt consumes ownership even on error. Never retry a handle value.
// Every value closed here is owned only by this process: the driver can force
// close the registration's device handle, and that handle is never here.
func (r *rings) closeWith(closeHandle func(windows.Handle) error) error {
	if r.closed {
		return nil
	}
	r.closed = true
	var err error
	retain := false
	if owner := r.owner; owner != nil {
		r.owner = nil
		retain, err = owner.end(r, closeHandle)
	}
	started := winclock.Now()
	for _, event := range []struct {
		value *windows.Handle
		owner winhandle.Owner
		site  string
	}{{&r.readEvent, r.readOwner, "Wintun read event close"}, {&r.writeEvent, r.writeOwner, "Wintun write event close"}} {
		if *event.value != 0 {
			if event.owner.IsZero() {
				err = errors.Join(err, closeHandle(*event.value))
			} else {
				err = errors.Join(err, event.owner.Close(event.site, closeHandle))
			}
			*event.value = 0
		}
	}
	r.closeProfile.EventsNanos = uint64(winclock.Since(started))
	started = winclock.Now()
	if retain {
		err = errors.Join(err, errRingsRetained) // The view intentionally lives until exit.
	} else if r.view != 0 {
		// The driver locked the registrar's view of these pages, never this one,
		// so unmapping here cannot free memory the driver may still write.
		err = errors.Join(err, windows.UnmapViewOfFile(r.view))
	}
	r.view = 0
	if !r.section.IsZero() {
		err = errors.Join(err, r.section.Close("Wintun ring section close", closeHandle))
		r.section = winhandle.Owner{}
	}
	r.closeProfile.MemoryNanos = uint64(winclock.Since(started))
	r.send.bytes, r.receive.bytes = nil, nil
	return err
}

func (r *rings) read(buffers [][]byte, sizes []int) (int, error) {
	var wordBatch uint64
	if wordBoundaryHooksEnabled {
		wordBatch = nextWordReadBatch()
	}
	tail := r.send.load(4)
	if tail == ^uint32(0) {
		return 0, ErrDisconnected
	}
	if r.send.load(0) != r.head {
		return 0, corrupt(r.send, "Send", "head changed", r.send.load(0), tail)
	}
	head := r.head
	i := 0
	for i < len(buffers) {
		packet, next, err := entry(r.send.data(), r.send.capacity, head, tail)
		if err == io.EOF {
			return i, nil
		}
		if err != nil {
			return i, corrupt(r.send, "Send", "invalid entry", head, tail)
		}
		if len(buffers[i]) < len(packet) {
			r.oversized++
		} else {
			copy(buffers[i], packet)
			// Validate a private copy before releasing any driver memory.
			p := buffers[i][:len(packet)]
			if wordBoundaryHooksEnabled {
				observeWordRingRead(p, head, wordBatch, i)
			}
			if integrityHooksEnabled {
				observeRingReceive(packet, p)
			}
			if binary.LittleEndian.Uint32(r.send.data()[head:head+4]) != uint32(len(packet)) {
				return i, corrupt(r.send, "Send", "packet length changed", head, tail)
			}
			if allZero(p) {
				// NdisGetDataBuffer failure leaves a sized zero placeholder.
				r.placeholders++
			} else if !validIP(p) {
				return i, corrupt(r.send, "Send", "packet failed validation", head, tail)
			} else {
				sizes[i] = len(packet)
				i++
			}
		}
		head = next
		r.head = head
		r.send.store(0, head)
	}
	return len(buffers), nil
}

func allZero(p []byte) bool {
	for _, b := range p {
		if b != 0 {
			return false
		}
	}
	return true
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
		if checksum.Checksum(p[:n], 0) != 65535 {
			return false
		}
		if binary.BigEndian.Uint16(p[6:8])&0x3fff != 0 {
			return true
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
	var inspection integrityRingBatch
	var wordInspection wordBoundaryBatch
	if wordBoundaryHooksEnabled {
		wordInspection = newWordBoundaryBatch()
	}
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
		if wordBoundaryHooksEnabled {
			wordInspection.add(data[tail+4:tail+4+uint32(len(p))], tail, written)
		}
		if integrityHooksEnabled {
			inspection.add(data[tail+4:tail+4+uint32(len(p))], p)
		}
		tail = (tail + size) & (capacity - 1)
		written++
	}
	if written != 0 {
		if wordBoundaryHooksEnabled {
			wordInspection.publish()
		}
		if integrityHooksEnabled {
			inspection.publish()
		}
		r.tail = tail
		r.receive.store(4, tail)
		// Never consult Receive.Alertable. An auto-reset event retains this
		// signal until the driver waits, including the store/load race in 0.14.1.
		err = windows.SetEvent(r.writeHandle())
	}
	return
}
