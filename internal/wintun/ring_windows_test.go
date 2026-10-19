//go:build windows

package wintun

import (
	"encoding/binary"
	"errors"
	"io"
	"net/netip"
	"testing"
	"unsafe"

	"github.com/AyoubAchour/net-switch/internal/engine/packet"
	"golang.org/x/sys/windows"
)

func testPacket() []byte {
	return packet.IP(netip.MustParseAddr("198.19.240.1"), netip.MustParseAddr("198.19.240.2"), 253, []byte("ring payload"))
}

func TestRingABI(t *testing.T) {
	if unsafe.Sizeof(registration{}) != 48 || unsafe.Offsetof(ringRegistration{}.Ring) != 8 || unsafe.Offsetof(ringRegistration{}.Event) != 16 {
		t.Fatal("wrong native registration layout")
	}
	if registerRingsIOCTL != 0xca6ce5c0 {
		t.Fatalf("IOCTL %x", registerRingsIOCTL)
	}
	for _, c := range []uint32{0, 1, MinCapacity - 4, MinCapacity + 4, MaxCapacity + 4} {
		if validCapacity(c) {
			t.Fatalf("accepted %d", c)
		}
	}
	for _, c := range []uint32{MinCapacity, MaxCapacity} {
		if !validCapacity(c) {
			t.Fatalf("rejected %d", c)
		}
	}
}

func TestRingEntries(t *testing.T) {
	const capacity = MinCapacity
	for _, tc := range []struct {
		name             string
		head, tail, size uint32
		want             error
	}{
		{"empty", 0, 0, 0, io.EOF},
		{"one", 0, 8, 1, nil},
		{"wrap", capacity - 4, 4, 1, nil},
		{"maximum", 0, 65540, MaxPacketSize, nil},
		{"zero", 0, 4, 0, ErrCorrupt},
		{"oversize", 0, 8, MaxPacketSize + 1, ErrCorrupt},
		{"partial", 0, 8, 5, ErrCorrupt},
		{"head alignment", 1, 8, 1, ErrCorrupt},
		{"tail alignment", 0, 9, 1, ErrCorrupt},
		{"head range", capacity, 8, 1, ErrCorrupt},
		{"tail range", 0, capacity, 1, ErrCorrupt},
		{"sentinel", 0, ^uint32(0), 1, ErrCorrupt},
	} {
		t.Run(tc.name, func(t *testing.T) {
			data := make([]byte, capacity+ringSlack)
			binary.LittleEndian.PutUint32(data[tc.head:tc.head+4], tc.size)
			p, next, err := entry(data, capacity, tc.head, tc.tail)
			if !errors.Is(err, tc.want) {
				t.Fatalf("error %v, want %v", err, tc.want)
			}
			if err == nil && (len(p) != int(tc.size) || next >= capacity || next&3 != 0) {
				t.Fatal("bad packet bounds")
			}
		})
	}
}

func TestRingBatchWakeAndFullDrop(t *testing.T) {
	event, err := windows.CreateEvent(nil, 0, 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer windows.CloseHandle(event)
	r := &rings{receive: ring{make([]byte, MinCapacity+ringHeader+ringSlack), MinCapacity}, writeEvent: event}
	p := testPacket()
	n, dropped, err := r.write([][]byte{p, p, p})
	if err != nil || n != 3 || dropped != 0 || r.receive.load(8) != 0 {
		t.Fatalf("%d %d %v", n, dropped, err)
	}
	// The event must retain its signal even though Alertable stayed false.
	if result, _ := windows.WaitForSingleObject(event, 0); result != windows.WAIT_OBJECT_0 {
		t.Fatal("missed unconditional wake")
	}
	if result, _ := windows.WaitForSingleObject(event, 0); result != uint32(windows.WAIT_TIMEOUT) {
		t.Fatal("event is not auto-reset")
	}
	r.receive.store(0, (r.tail+4)&(MinCapacity-1))
	n, dropped, err = r.write([][]byte{p, p})
	if err != nil || n != 0 || dropped != 2 {
		t.Fatalf("full ring: %d %d %v", n, dropped, err)
	}
	if result, _ := windows.WaitForSingleObject(event, 0); result != uint32(windows.WAIT_TIMEOUT) {
		t.Fatal("empty batch woke driver")
	}
}

func TestRingReadRejectsDamagedPacket(t *testing.T) {
	r := &rings{send: ring{make([]byte, MinCapacity+ringHeader+ringSlack), MinCapacity}}
	p := testPacket()
	p[2] ^= 1
	binary.LittleEndian.PutUint32(r.send.data(), uint32(len(p)))
	copy(r.send.data()[4:], p)
	r.send.store(4, aligned(uint32(len(p))+4))
	n, err := r.read([][]byte{make([]byte, MaxPacketSize)}, make([]int, 1))
	if n != 0 || !errors.Is(err, ErrCorrupt) || r.send.load(0) != 0 {
		t.Fatalf("damaged packet escaped: %d %v", n, err)
	}
}

func FuzzRingEntry(f *testing.F) {
	f.Add(uint32(0), uint32(8), uint32(1), []byte{1})
	f.Add(uint32(MinCapacity-4), uint32(4), uint32(65536), []byte{0x45})
	f.Fuzz(func(t *testing.T, head, tail, size uint32, body []byte) {
		data := make([]byte, MinCapacity+ringSlack)
		if head < MinCapacity {
			binary.LittleEndian.PutUint32(data[head:head+4], size)
			copy(data[head+4:], body)
		}
		p, next, err := entry(data, MinCapacity, head, tail)
		if err == nil {
			if len(p) == 0 || len(p) > MaxPacketSize || next >= MinCapacity || next&3 != 0 {
				t.Fatal("parser admitted invalid bounds")
			}
			validIP(p) // Fuzz the post-copy validation too.
		}
	})
}
