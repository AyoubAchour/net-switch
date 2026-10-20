//go:build windows

// Package winengine implements the Windows engine boundary. It does not manage
// services, the desktop application, or the legacy engine.
package winengine

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/AyoubAchour/net-switch/internal/apppath"
	"github.com/AyoubAchour/net-switch/internal/engine/platform"
	"golang.org/x/sys/windows"
)

var iphlp = windows.NewLazySystemDLL("iphlpapi.dll")
var tcpTable = iphlp.NewProc("GetExtendedTcpTable")
var udpTable = iphlp.NewProc("GetExtendedUdpTable")
var errOwnerMissing = errors.New("socket owner not found")

// All states, including SYN_SENT. Filtering for ESTABLISHED loses the very
// sockets whose SYN is waiting for the engine's admission decision.
const tcpOwnerPIDAll = 5
const udpOwnerModule = 2

type processKey struct {
	pid   uint32
	start uint64
}
type socketOwner struct {
	pid     uint32
	created uint64
}
type ownerSnapshot struct {
	at   time.Time
	rows map[platform.Tuple][]uint32
	err  error
}

type LookupHistogram struct {
	Count     uint64 `json:"count"`
	Misses    uint64 `json:"misses"`
	Ambiguous uint64 `json:"ambiguous"`
	// Non-cumulative buckets, upper bounds in microseconds, last = infinity.
	UpperUS []uint64 `json:"upperUS"`
	Buckets []uint64 `json:"buckets"`
	MaxUS   uint64   `json:"maxUS"`
}

var lookupBounds = [...]uint64{100, 250, 500, 1000, 2000, 3000, 4000, 5000, 10000, 20000, 50000, ^uint64(0)}

type Owners struct {
	mu                              sync.Mutex
	snapshot                        ownerSnapshot
	refresh                         chan struct{}
	paths                           map[processKey]string
	hist                            [len(lookupBounds)]atomic.Uint64
	count, misses, ambiguous, maxUS atomic.Uint64
}

func NewOwners() *Owners { return &Owners{paths: make(map[processKey]string)} }

func (o *Owners) measure(start time.Time, err error) {
	us := uint64(max(0, time.Since(start).Microseconds()))
	o.count.Add(1)
	if err != nil {
		o.misses.Add(1)
		if errors.Is(err, platform.ErrAmbiguous) {
			o.ambiguous.Add(1)
		}
	}
	for i, upper := range lookupBounds {
		if us <= upper {
			o.hist[i].Add(1)
			break
		}
	}
	for old := o.maxUS.Load(); us > old; old = o.maxUS.Load() {
		if o.maxUS.CompareAndSwap(old, us) {
			break
		}
	}
}

func (o *Owners) Stats() LookupHistogram {
	h := LookupHistogram{Count: o.count.Load(), Misses: o.misses.Load(), Ambiguous: o.ambiguous.Load(), MaxUS: o.maxUS.Load(),
		UpperUS: append([]uint64(nil), lookupBounds[:]...), Buckets: make([]uint64, len(lookupBounds))}
	for i := range h.Buckets {
		h.Buckets[i] = o.hist[i].Load()
	}
	return h
}

func readOwnerTable(ctx context.Context, proc *windows.LazyProc, family, class uint32) ([]byte, error) {
	size := uint32(32 << 10)
	for attempt := 0; attempt < 8; attempt++ {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if size < 4 || size > 64<<20 {
			return nil, errors.New("IP Helper table size outside budget")
		}
		b := make([]byte, size)
		code, _, _ := proc.Call(uintptr(unsafe.Pointer(&b[0])), uintptr(unsafe.Pointer(&size)), 0, uintptr(family), uintptr(class), 0)
		if code == uintptr(windows.ERROR_INSUFFICIENT_BUFFER) {
			continue
		}
		if code != 0 {
			return nil, fmt.Errorf("%s: %w", proc.Name, windows.Errno(code))
		}
		if size > uint32(len(b)) {
			return nil, errors.New("IP Helper returned an oversized table")
		}
		return b[:size], ctx.Err()
	}
	return nil, errors.New("IP Helper table kept growing")
}

func ownerRows(b []byte, offset, stride int) ([][]byte, error) {
	if len(b) < 4 {
		return nil, errors.New("truncated owner table")
	}
	count := uint64(binary.LittleEndian.Uint32(b))
	if count == 0 {
		return nil, nil
	}
	if offset > len(b) || count > uint64((len(b)-offset)/stride) {
		return nil, errors.New("truncated owner rows")
	}
	rows := make([][]byte, int(count))
	for i := range rows {
		rows[i] = b[offset+i*stride : offset+(i+1)*stride]
	}
	return rows, nil
}

func parseTCP(b []byte, v6 bool, rows map[platform.Tuple][]uint32) error {
	stride := 24
	if v6 {
		stride = 56
	}
	raw, err := ownerRows(b, 4, stride)
	if err != nil {
		return err
	}
	for _, r := range raw {
		var src, dst netip.Addr
		var sp, dp uint16
		var pid uint32
		if v6 {
			src, dst = netip.AddrFrom16([16]byte(r[:16])), netip.AddrFrom16([16]byte(r[24:40]))
			sp, dp = binary.BigEndian.Uint16(r[20:]), binary.BigEndian.Uint16(r[44:])
			pid = binary.LittleEndian.Uint32(r[52:])
		} else {
			src, dst = netip.AddrFrom4([4]byte(r[4:8])), netip.AddrFrom4([4]byte(r[12:16]))
			sp, dp = binary.BigEndian.Uint16(r[8:]), binary.BigEndian.Uint16(r[16:])
			pid = binary.LittleEndian.Uint32(r[20:])
		}
		if pid == 0 {
			continue
		}
		key := platform.Tuple{Source: netip.AddrPortFrom(src.Unmap(), sp), Destination: netip.AddrPortFrom(dst.Unmap(), dp)}
		rows[key] = append(rows[key], pid)
	}
	return nil
}

// One refresh is shared by all callers. Waiting for it remains cancellable;
// process image queries never hold the snapshot mutex.
func (o *Owners) tcpSnapshot(ctx context.Context) (ownerSnapshot, error) {
	for {
		o.mu.Lock()
		if !o.snapshot.at.IsZero() && time.Since(o.snapshot.at) < 5*time.Millisecond {
			s := o.snapshot
			o.mu.Unlock()
			return s, s.err
		}
		if done := o.refresh; done != nil {
			o.mu.Unlock()
			select {
			case <-ctx.Done():
				return ownerSnapshot{}, ctx.Err()
			case <-done:
				o.mu.Lock()
				s := o.snapshot
				o.mu.Unlock()
				return s, s.err
			}
		}
		done := make(chan struct{})
		o.refresh = done
		o.mu.Unlock()
		s := ownerSnapshot{at: time.Now(), rows: make(map[platform.Tuple][]uint32)}
		for _, family := range []uint32{windows.AF_INET, windows.AF_INET6} {
			b, err := readOwnerTable(ctx, tcpTable, family, tcpOwnerPIDAll)
			if err == nil {
				err = parseTCP(b, family == windows.AF_INET6, s.rows)
			}
			if err != nil {
				s.err = err
				break
			}
		}
		o.mu.Lock()
		o.snapshot = s
		o.refresh = nil
		close(done)
		o.mu.Unlock()
		return s, s.err
	}
}

func (o *Owners) process(pid uint32) (platform.Owner, error) {
	if pid == 0 {
		return platform.Owner{}, errOwnerMissing
	}
	if pid == 4 {
		return platform.Owner{PID: 4, Path: "System", AppID: "system"}, nil
	}
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return platform.Owner{}, err
	}
	defer windows.CloseHandle(h)
	var creation, exit, kernel, user windows.Filetime
	if err := windows.GetProcessTimes(h, &creation, &exit, &kernel, &user); err != nil {
		return platform.Owner{}, err
	}
	start := uint64(creation.HighDateTime)<<32 | uint64(creation.LowDateTime)
	key := processKey{pid, start}
	o.mu.Lock()
	path := o.paths[key]
	o.mu.Unlock()
	if path == "" {
		b := make([]uint16, 32768)
		n := uint32(len(b))
		if err := windows.QueryFullProcessImageName(h, 0, &b[0], &n); err != nil {
			return platform.Owner{}, err
		}
		path = windows.UTF16ToString(b[:n])
		o.mu.Lock()
		// Bounded cache: a PID is always revalidated by its open process handle.
		if len(o.paths) >= 4096 {
			clear(o.paths)
		}
		o.paths[key] = path
		o.mu.Unlock()
	}
	return platform.Owner{PID: pid, StartTime: start, Path: path, AppID: apppath.Key(path)}, nil
}

func (o *Owners) TCP(ctx context.Context, tuple platform.Tuple) (owner platform.Owner, err error) {
	start := time.Now()
	defer func() { o.measure(start, err) }()
	ctx, cancel := context.WithTimeout(ctx, 50*time.Millisecond)
	defer cancel()
	for attempt := 0; attempt < 3; attempt++ {
		if attempt != 0 {
			select {
			case <-time.After(3 * time.Millisecond):
			case <-ctx.Done():
				return owner, ctx.Err()
			}
		}
		s, e := o.tcpSnapshot(ctx)
		if e != nil {
			return owner, e
		}
		pids := s.rows[tuple]
		if len(pids) > 1 {
			return owner, platform.ErrAmbiguous
		}
		if len(pids) == 1 {
			return o.process(pids[0])
		}
	}
	return owner, errOwnerMissing
}

func parseUDP(b []byte, v6 bool, rows map[netip.AddrPort][]socketOwner) error {
	stride := 160
	if v6 {
		stride = 176
	}
	raw, err := ownerRows(b, 8, stride)
	if err != nil {
		return err
	}
	for _, r := range raw {
		var addr netip.Addr
		var port uint16
		var pid uint32
		var created uint64
		if v6 {
			addr = netip.AddrFrom16([16]byte(r[:16]))
			port = binary.BigEndian.Uint16(r[20:])
			pid = binary.LittleEndian.Uint32(r[24:])
			created = binary.LittleEndian.Uint64(r[32:])
		} else {
			addr = netip.AddrFrom4([4]byte(r[:4]))
			port = binary.BigEndian.Uint16(r[4:])
			pid = binary.LittleEndian.Uint32(r[8:])
			created = binary.LittleEndian.Uint64(r[16:])
		}
		key := netip.AddrPortFrom(addr, port)
		rows[key] = append(rows[key], socketOwner{pid, created})
	}
	return nil
}

func (o *Owners) udpOwner(key netip.AddrPort, rows map[netip.AddrPort][]socketOwner) (platform.Owner, error) {
	candidates := rows[key]
	if len(candidates) == 0 {
		any := netip.IPv4Unspecified()
		if key.Addr().Is6() {
			any = netip.IPv6Unspecified()
		}
		candidates = rows[netip.AddrPortFrom(any, key.Port())]
	}
	if len(candidates) > 1 {
		return platform.Owner{}, platform.ErrAmbiguous
	}
	if len(candidates) == 0 || candidates[0].created == 0 {
		return platform.Owner{}, errOwnerMissing
	}
	r := candidates[0]
	owner, err := o.process(r.pid)
	owner.Generation = strconv.FormatUint(r.created, 16)
	return owner, err
}

func (o *Owners) UDP(ctx context.Context, key netip.AddrPort) (owner platform.Owner, err error) {
	start := time.Now()
	defer func() { o.measure(start, err) }()
	family := uint32(windows.AF_INET)
	if key.Addr().Is6() {
		family = windows.AF_INET6
	}
	b, err := readOwnerTable(ctx, udpTable, family, udpOwnerModule)
	if err != nil {
		return owner, err
	}
	rows := make(map[netip.AddrPort][]socketOwner)
	if err = parseUDP(b, key.Addr().Is6(), rows); err != nil {
		return owner, err
	}
	return o.udpOwner(key, rows)
}

// The NAT invokes this once per second, even in the absence of traffic. One
// complete read per family covers every session. A partial read fails the whole
// validation; the NAT's two-second stale guard then stops both directions.
func (o *Owners) Snapshot(ctx context.Context, keys []netip.AddrPort) (map[netip.AddrPort]platform.Owner, error) {
	rows := make(map[netip.AddrPort][]socketOwner)
	families := map[uint32]bool{}
	for _, key := range keys {
		family := uint32(windows.AF_INET)
		if key.Addr().Is6() {
			family = windows.AF_INET6
		}
		families[family] = true
	}
	for family := range families {
		b, err := readOwnerTable(ctx, udpTable, family, udpOwnerModule)
		if err != nil {
			return nil, err
		}
		if err := parseUDP(b, family == windows.AF_INET6, rows); err != nil {
			return nil, err
		}
	}
	out := make(map[netip.AddrPort]platform.Owner, len(keys))
	for _, key := range keys {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		owner, err := o.udpOwner(key, rows)
		if err == nil {
			out[key] = owner
		}
	}
	return out, nil
}
