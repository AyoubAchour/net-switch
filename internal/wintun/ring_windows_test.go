//go:build windows

package wintun

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
	"unsafe"

	"github.com/AyoubAchour/net-switch/internal/engine/packet"
	"golang.org/x/sys/windows"
	"gvisor.dev/gvisor/pkg/tcpip/checksum"
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

func TestPinnedDLLMatchesDistribution(t *testing.T) {
	_, source, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("source path unavailable")
	}
	data, err := os.ReadFile(filepath.Join(filepath.Dir(source), "../../packaging/versions.json"))
	if err != nil {
		t.Fatal(err)
	}
	var pins struct {
		NativeSources struct {
			Wintun struct{ EmbeddedAmd64Sha256, EmbeddedArm64Sha256 string }
		}
	}
	if err := json.Unmarshal(data, &pins); err != nil {
		t.Fatal(err)
	}
	if pins.NativeSources.Wintun.EmbeddedAmd64Sha256 != pinnedDLL["amd64"] || pins.NativeSources.Wintun.EmbeddedArm64Sha256 != pinnedDLL["arm64"] {
		t.Fatal("runtime DLL hashes differ from distribution pins")
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

func TestRingRecoveryInjectionSurvivesPublication(t *testing.T) {
	for _, publish := range []bool{false, true} {
		t.Run(fmt.Sprint(publish), func(t *testing.T) {
			r := &rings{send: ring{make([]byte, MinCapacity+ringHeader+ringSlack), MinCapacity}}
			injectRecoveryFault(r)
			if publish {
				// An in-flight driver send can publish its reserved packet even
				// while the test owns Session.mu. Reproduce that ordering.
				p := testPacket()
				binary.LittleEndian.PutUint32(r.send.data(), uint32(len(p)))
				copy(r.send.data()[4:], p)
				r.send.store(4, aligned(uint32(len(p))+4))
			}
			n, err := r.read([][]byte{make([]byte, MaxPacketSize)}, make([]int, 1))
			if n != 0 || !errors.Is(err, ErrCorrupt) {
				t.Fatalf("driver publication erased the recovery injection: %d %v", n, err)
			}
		})
	}
}

// The next three tests cover the test-only in-process baseline owner, which
// must stay faithful to the former production close for comparisons.
func TestRingDisconnectedHandleIsNotClosedTwice(t *testing.T) {
	// Simulate the numeric device handle having been reused for a new event
	// after the driver closed the original and published its disconnect marker.
	reused, err := windows.CreateEvent(nil, 0, 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer windows.CloseHandle(reused)
	r, err := allocateRings(MinCapacity)
	if err != nil {
		t.Fatal(err)
	}
	r.owner = &inProcessOwner{device: reused, registered: true}
	r.send.store(4, ^uint32(0))
	if err := r.close(); err != nil {
		t.Fatal(err)
	}
	if result, err := windows.WaitForSingleObject(reused, 0); err != nil || result != uint32(windows.WAIT_TIMEOUT) {
		t.Fatalf("closed a reused handle: %d %v", result, err)
	}
}

func TestRingWriteSideRemovalWaitsForTail(t *testing.T) {
	r, err := allocateRings(MinCapacity)
	must(t, err)
	reused, err := windows.CreateEvent(nil, 0, 0, nil)
	must(t, err)
	defer windows.CloseHandle(reused)
	r.owner = &inProcessOwner{device: reused, registered: true}
	r.receive.store(0, ^uint32(0))
	send := r.send
	done := make(chan struct{})
	go func() {
		time.Sleep(20 * time.Millisecond)
		send.store(4, ^uint32(0))
		close(done)
	}()
	must(t, r.close())
	<-done
	must(t, r.close())
	must(t, windows.SetEvent(reused))
}

func TestRingFailedCloseSurvivesGC(t *testing.T) {
	for _, writeDisconnected := range []bool{false, true} {
		t.Run(fmt.Sprint(writeDisconnected), func(t *testing.T) {
			r, err := allocateRings(MinCapacity)
			must(t, err)
			address := r.view
			// There is no driver in this unit test; release the deliberately
			// retained view ourselves after checking its post-GC lifetime.
			defer windows.UnmapViewOfFile(address)
			owner := &inProcessOwner{device: windows.Handle(123), registered: true}
			r.owner = owner
			if writeDisconnected {
				r.receive.store(0, ^uint32(0))
			}
			calls := 0
			closeHandle := func(h windows.Handle) error {
				if h != 123 {
					return windows.CloseHandle(h) // the section is a real owned handle
				}
				calls++
				return windows.ERROR_INVALID_HANDLE
			}
			err = r.closeWith(closeHandle)
			if !errors.Is(err, errRingsRetained) || (!writeDisconnected && !errors.Is(err, windows.ERROR_INVALID_HANDLE)) {
				t.Fatal(err)
			}
			if owner.device != 0 {
				t.Fatal("retained stale handle")
			}
			must(t, r.closeWith(closeHandle))
			want := 1
			if writeDisconnected {
				want = 0
			}
			if calls != want {
				t.Fatalf("CloseHandle calls: %d, want %d", calls, want)
			}
			r = nil
			runtime.GC()
			runtime.GC()
			var info windows.MemoryBasicInformation
			must(t, windows.VirtualQuery(address, &info, unsafe.Sizeof(info)))
			if info.State != windows.MEM_COMMIT {
				t.Fatal("freed memory before driver termination")
			}
		})
	}
}

func TestRingDropsPlaceholdersAndOversizedPackets(t *testing.T) {
	for _, kind := range []string{"placeholder", "oversized", "nonzero damage"} {
		t.Run(kind, func(t *testing.T) {
			r, err := allocateRings(MinCapacity)
			must(t, err)
			defer r.close()
			first := make([]byte, 20)
			if kind == "oversized" {
				first = packet.IP(netip.MustParseAddr("198.19.240.1"), netip.MustParseAddr("198.19.240.2"), 253, make([]byte, 10000))
			} else if kind == "nonzero damage" {
				first[0] = 0x45
			}
			next := aligned(uint32(len(first)) + 4)
			binary.LittleEndian.PutUint32(r.send.data(), uint32(len(first)))
			copy(r.send.data()[4:], first)
			p := testPacket()
			binary.LittleEndian.PutUint32(r.send.data()[next:], uint32(len(p)))
			copy(r.send.data()[next+4:], p)
			r.send.store(4, next+aligned(uint32(len(p))+4))
			buf, sizes := make([]byte, 9000), make([]int, 1)
			n, err := r.read([][]byte{buf}, sizes)
			if kind == "nonzero damage" {
				if n != 0 || !errors.Is(err, ErrCorrupt) {
					t.Fatalf("damage escaped: %d %v", n, err)
				}
				return
			}
			if n != 1 || err != nil || !bytes.Equal(buf[:sizes[0]], p) || r.head != r.send.load(4) {
				t.Fatalf("reader stuck after %s: %d %v", kind, n, err)
			}
			if (kind == "placeholder" && r.placeholders != 1) || (kind == "oversized" && r.oversized != 1) {
				t.Fatal("drop was not counted")
			}
		})
	}
}

func TestRingFragmentHeaderChecksum(t *testing.T) {
	p := testPacket()
	p[6] = 0x20
	p[10], p[11] = 0, 0
	binary.BigEndian.PutUint16(p[10:12], ^checksum.Checksum(p[:20], 0))
	if !validIP(p) {
		t.Fatal("valid fragment rejected")
	}
	p[8] ^= 1
	if validIP(p) {
		t.Fatal("bad fragment header accepted")
	}
}

func TestRingChecksumHandoff(t *testing.T) {
	s := &Session{}
	for _, pair := range [][2]string{{"198.18.0.1:1234", "198.18.0.2:4321"}, {"[fd00::1]:1234", "[fd00::2]:4321"}} {
		p := packet.UDP(netip.MustParseAddrPort(pair[0]), netip.MustParseAddrPort(pair[1]), []byte("checksum"))
		if !validIP(p) || !s.RXChecksumVerified(p) {
			t.Fatal("verified UDP lost checksum metadata")
		}
		p[len(p)-1] ^= 1
		if validIP(p) {
			t.Fatal("damaged UDP accepted")
		}
		p[len(p)-1] ^= 1
		if p[0]>>4 == 4 {
			p[6] = 0x20
		} else {
			p[6] = 44
		}
		if s.RXChecksumVerified(p) {
			t.Fatal("fragment bypasses stack checksum verification")
		}
	}
	if s.RXChecksumVerified(testPacket()) {
		t.Fatal("unverified protocol bypasses stack checks")
	}
}

func TestRingReadyBatchDoesNotAllocate(t *testing.T) {
	r, err := allocateRings(MinCapacity)
	must(t, err)
	defer r.close()
	p := testPacket()
	binary.LittleEndian.PutUint32(r.send.data(), uint32(len(p)))
	copy(r.send.data()[4:], p)
	r.send.store(4, aligned(uint32(len(p))+4))
	s := &Session{rings: r}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	buffers, sizes := [][]byte{make([]byte, 9000)}, make([]int, 1)
	allocs := testing.AllocsPerRun(1000, func() {
		r.head = 0
		r.send.store(0, 0)
		n, err := s.ReadBatch(ctx, buffers, sizes)
		if err != nil || n != 1 {
			t.Fatalf("read %d: %v", n, err)
		}
	})
	if allocs != 0 {
		t.Fatalf("ready read allocated %.2f times", allocs)
	}
	t.Logf("1000 ready batches: %.0f allocations per batch", allocs)
}

func TestRingReopenBackoff(t *testing.T) {
	stop := make(chan struct{})
	calls := 0
	start := time.Now()
	want := &rings{}
	r, err := reopenRings(stop, func() (*rings, error) {
		calls++
		if calls < 3 {
			return nil, windows.ERROR_ALREADY_INITIALIZED
		}
		return want, nil
	})
	if r != want || err != nil || calls != 3 || time.Since(start) < 30*time.Millisecond {
		t.Fatalf("retry: %d %v", calls, err)
	}
	close(stop)
	_, err = reopenRings(stop, func() (*rings, error) { return nil, windows.ERROR_ALREADY_INITIALIZED })
	if !errors.Is(err, net.ErrClosed) {
		t.Fatal(err)
	}
	if got := windows.STATUS_ALREADY_INITIALIZED.Errno(); got != windows.ERROR_ALREADY_INITIALIZED {
		t.Fatalf("unexpected NTSTATUS mapping: %v", got)
	}
}

func TestRingDLLLoadRetriesFailure(t *testing.T) {
	var cache libraryCache
	calls := 0
	load := func() (*library, error) {
		calls++
		if calls == 1 {
			return nil, windows.ERROR_FILE_NOT_FOUND
		}
		return &library{}, nil
	}
	if _, err := cache.get(load); err == nil {
		t.Fatal("missing DLL accepted")
	}
	a, err := cache.get(load)
	must(t, err)
	b, err := cache.get(load)
	must(t, err)
	if a != b || calls != 2 {
		t.Fatal("did not cache only success")
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
