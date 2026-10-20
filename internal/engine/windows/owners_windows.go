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
	at      time.Time
	rows    tcpIndex
	err     error
	rawRows uint64
}

type tcpCandidates struct {
	pid, count uint32
}

// Native tuples have no Go address-zone handles or struct padding. Keep the
// snapshot keys equally compact: 12 bytes for IPv4, 36 for IPv6. In particular,
// an IPv4 dump must not allocate a 64-byte platform.Tuple key for every row.
type tcpIndex struct {
	v4 map[[12]byte]tcpCandidates
	v6 map[[36]byte]tcpCandidates
}

func tcp4Key(tuple platform.Tuple) [12]byte {
	var key [12]byte
	source, destination := tuple.Source.Addr().As4(), tuple.Destination.Addr().As4()
	copy(key[:4], source[:])
	copy(key[4:8], destination[:])
	binary.BigEndian.PutUint16(key[8:10], tuple.Source.Port())
	binary.BigEndian.PutUint16(key[10:12], tuple.Destination.Port())
	return key
}
func tcp6Key(tuple platform.Tuple) [36]byte {
	var key [36]byte
	source, destination := tuple.Source.Addr().As16(), tuple.Destination.Addr().As16()
	copy(key[:16], source[:])
	copy(key[16:32], destination[:])
	binary.BigEndian.PutUint16(key[32:34], tuple.Source.Port())
	binary.BigEndian.PutUint16(key[34:36], tuple.Destination.Port())
	return key
}
func (index tcpIndex) find(tuple platform.Tuple) tcpCandidates {
	if tuple.Source.Addr().Is4() && tuple.Destination.Addr().Is4() {
		return index.v4[tcp4Key(tuple)]
	}
	return index.v6[tcp6Key(tuple)]
}
func (index *tcpIndex) add(tuple platform.Tuple, pid uint32) {
	if tuple.Source.Addr().Is4() && tuple.Destination.Addr().Is4() {
		if index.v4 == nil {
			index.v4 = make(map[[12]byte]tcpCandidates)
		}
		key := tcp4Key(tuple)
		value := index.v4[key]
		value.pid, value.count = pid, value.count+1
		index.v4[key] = value
	} else {
		if index.v6 == nil {
			index.v6 = make(map[[36]byte]tcpCandidates)
		}
		key := tcp6Key(tuple)
		value := index.v6[key]
		value.pid, value.count = pid, value.count+1
		index.v6[key] = value
	}
}

type tcpRefresh struct {
	done   chan struct{}
	result *ownerSnapshot
}

type LookupHistogram struct {
	Count     uint64 `json:"count"`
	Misses    uint64 `json:"misses"`
	Ambiguous uint64 `json:"ambiguous"`
	// Non-cumulative buckets, upper bounds in microseconds, last = infinity.
	UpperUS            []uint64  `json:"upperUS"`
	Buckets            []uint64  `json:"buckets"`
	MaxUS              uint64    `json:"maxUS"`
	TCPRefreshes       uint64    `json:"tcpRefreshes"`
	TCPReadNanos       uint64    `json:"tcpReadNanos"`
	TCPIndexNanos      uint64    `json:"tcpIndexNanos"`
	CacheMissRefreshes uint64    `json:"cacheMissRefreshes"`
	TCPRetries         uint64    `json:"tcpRetries"`
	SnapshotBuckets    []uint64  `json:"snapshotBuckets"`
	ProcessBuckets     []uint64  `json:"processBuckets"`
	RefreshBuckets     []uint64  `json:"refreshBuckets"`
	TCPRawRows         uint64    `json:"tcpRawRows"`
	TCPPeakRows        uint64    `json:"tcpPeakRows"`
	TCPRowsByFamily    [2]uint64 `json:"tcpRowsByFamily"`
	TCPFamiliesSampled [2]bool   `json:"tcpFamiliesSampled"`
}

var lookupBounds = [...]uint64{100, 250, 500, 1000, 2000, 3000, 4000, 5000, 10000, 20000, 50000, ^uint64(0)}

type Owners struct {
	mu                                                            sync.Mutex
	snapshot                                                      [2]atomic.Pointer[ownerSnapshot]
	refresh                                                       [2]atomic.Pointer[tcpRefresh]
	paths                                                         map[processKey]platform.Owner
	tcpBuffers                                                    [2][]byte
	hist                                                          [len(lookupBounds)]atomic.Uint64
	snapshotHist, processHist                                     [len(lookupBounds)]atomic.Uint64
	refreshHist                                                   [len(lookupBounds)]atomic.Uint64
	count, misses, ambiguous, maxUS                               atomic.Uint64
	tcpRefreshes, tcpReadNanos, tcpIndexNanos, cacheMissRefreshes atomic.Uint64
	tcpRetries                                                    atomic.Uint64
	tcpPeakRows                                                   atomic.Uint64
}

func NewOwners() *Owners { return &Owners{paths: make(map[processKey]platform.Owner)} }

func measureStage(hist *[len(lookupBounds)]atomic.Uint64, start time.Time) {
	us := uint64(max(0, time.Since(start).Microseconds()))
	for i, bound := range lookupBounds {
		if us <= bound {
			hist[i].Add(1)
			return
		}
	}
}

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
		UpperUS: append([]uint64(nil), lookupBounds[:]...), Buckets: make([]uint64, len(lookupBounds)),
		TCPRetries: o.tcpRetries.Load(), SnapshotBuckets: make([]uint64, len(lookupBounds)), ProcessBuckets: make([]uint64, len(lookupBounds)), RefreshBuckets: make([]uint64, len(lookupBounds))}
	h.TCPRefreshes, h.TCPReadNanos, h.TCPIndexNanos, h.CacheMissRefreshes = o.tcpRefreshes.Load(), o.tcpReadNanos.Load(), o.tcpIndexNanos.Load(), o.cacheMissRefreshes.Load()
	h.TCPPeakRows = o.tcpPeakRows.Load()
	for family := range o.snapshot {
		if snapshot := o.snapshot[family].Load(); snapshot != nil {
			h.TCPRowsByFamily[family] = snapshot.rawRows
			h.TCPFamiliesSampled[family] = true
			h.TCPRawRows += snapshot.rawRows
		}
	}
	for i := range h.Buckets {
		h.Buckets[i] = o.hist[i].Load()
		h.SnapshotBuckets[i], h.ProcessBuckets[i] = o.snapshotHist[i].Load(), o.processHist[i].Load()
		h.RefreshBuckets[i] = o.refreshHist[i].Load()
	}
	return h
}

func readOwnerTable(ctx context.Context, proc *windows.LazyProc, family, class uint32) ([]byte, error) {
	var scratch []byte
	return readOwnerTableInto(ctx, proc, family, class, &scratch)
}

func readOwnerTableInto(ctx context.Context, proc *windows.LazyProc, family, class uint32, scratch *[]byte) ([]byte, error) {
	size := uint32(max(32<<10, cap(*scratch)))
	for attempt := 0; attempt < 8; attempt++ {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if size < 4 || size > 64<<20 {
			return nil, errors.New("IP Helper table size outside budget")
		}
		if cap(*scratch) < int(size) {
			*scratch = make([]byte, size)
		}
		b := (*scratch)[:size]
		code, _, _ := proc.Call(uintptr(unsafe.Pointer(&b[0])), uintptr(unsafe.Pointer(&size)), 0, uintptr(family), uintptr(class), 0)
		if code == uintptr(windows.ERROR_INSUFFICIENT_BUFFER) {
			// Leave room for endpoints admitted between the sizing call and
			// the read, rather than reallocating for each row in a burst.
			if size <= 48<<20 {
				size = (size + size/4 + 4095) &^ 4095
			}
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

func parseTCP(b []byte, v6 bool, rows *tcpIndex) error {
	stride := 24
	if v6 {
		stride = 56
	}
	if len(b) < 4 || uint64(binary.LittleEndian.Uint32(b)) > uint64((len(b)-4)/stride) {
		return errors.New("truncated TCP owner rows")
	}
	for i, count := 0, int(binary.LittleEndian.Uint32(b)); i < count; i++ {
		r := b[4+i*stride : 4+(i+1)*stride]
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
		rows.add(key, pid)
	}
	return nil
}

// GetExtendedTcpTable accepts one family per call. A five-millisecond snapshot
// and one in-flight refresh are shared by all SYNs of that family. A lookup
// never waits for the unrelated family's dump. Both waits remain cancellable.
func (o *Owners) tcpSnapshot(ctx context.Context, after time.Time, family int) (ownerSnapshot, error) {
	start := time.Now()
	defer measureStage(&o.snapshotHist, start)
	for {
		if err := ctx.Err(); err != nil {
			return ownerSnapshot{}, err
		}
		if s := o.snapshot[family].Load(); s != nil && s.at.After(after) && time.Since(s.at) < 5*time.Millisecond {
			return *s, s.err
		}
		pending := o.refresh[family].Load()
		if pending == nil {
			pending = &tcpRefresh{done: make(chan struct{})}
			if !o.refresh[family].CompareAndSwap(nil, pending) {
				continue
			}
			// A different refresh may have published between our two loads.
			// Reuse it rather than starting another dump after winning the slot.
			if s := o.snapshot[family].Load(); s != nil && s.at.After(after) && time.Since(s.at) < 5*time.Millisecond {
				pending.result = s
				o.refresh[family].Store(nil)
				close(pending.done)
				return *s, s.err
			}
			go o.refreshTCP(pending, family)
		}
		select {
		case <-ctx.Done():
			return ownerSnapshot{}, ctx.Err()
		case <-pending.done:
			s := pending.result
			if !s.at.After(after) {
				continue
			}
			return *s, s.err
		}
	}
}

func (o *Owners) refreshTCP(pending *tcpRefresh, family int) {
	// The IP Helper call is synchronous and cannot be cancelled. Keep at
	// most one snapshot per family in flight, while every lookup can leave at
	// its own 50 ms deadline. One caller's cancellation cannot poison peers.
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	s := ownerSnapshot{at: time.Now()}
	o.tcpRefreshes.Add(1)
	af, stride := uint32(windows.AF_INET), 24
	if family == 1 {
		af, stride = windows.AF_INET6, 56
	}
	readStart := time.Now()
	b, err := readOwnerTableInto(ctx, tcpTable, af, tcpOwnerPIDAll, &o.tcpBuffers[family])
	o.tcpReadNanos.Add(uint64(time.Since(readStart)))
	s.err = err
	if s.err == nil {
		indexStart := time.Now()
		// One scalar value per tuple avoids allocating a slice for every row.
		if family == 0 {
			s.rows.v4 = make(map[[12]byte]tcpCandidates, len(b)/stride)
		} else {
			s.rows.v6 = make(map[[36]byte]tcpCandidates, len(b)/stride)
		}
		s.err = parseTCP(b, family == 1, &s.rows)
		if s.err == nil {
			s.rawRows = uint64(binary.LittleEndian.Uint32(b))
		}
		o.tcpIndexNanos.Add(uint64(time.Since(indexStart)))
	}
	measureStage(&o.refreshHist, s.at)
	rows := s.rawRows
	if other := o.snapshot[1-family].Load(); other != nil {
		rows += other.rawRows
	}
	for old := o.tcpPeakRows.Load(); rows > old; old = o.tcpPeakRows.Load() {
		if o.tcpPeakRows.CompareAndSwap(old, rows) {
			break
		}
	}
	// The map and result never change after publication. Wake-up readers
	// need no shared mutex, including the burst immediately after a dump.
	pending.result = &s
	o.snapshot[family].Store(&s)
	o.refresh[family].Store(nil)
	close(pending.done)
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
	cached := o.paths[key]
	o.mu.Unlock()
	if cached.Path == "" {
		b := make([]uint16, 32768)
		n := uint32(len(b))
		if err := windows.QueryFullProcessImageName(h, 0, &b[0], &n); err != nil {
			return platform.Owner{}, err
		}
		path := windows.UTF16ToString(b[:n])
		cached = platform.Owner{PID: pid, StartTime: start, Path: path, AppID: apppath.Key(path)}
		o.mu.Lock()
		// Bounded cache: a PID is always revalidated by its open process handle.
		if len(o.paths) >= 4096 {
			clear(o.paths)
		}
		o.paths[key] = cached
		o.mu.Unlock()
	}
	return cached, nil
}

func (o *Owners) TCP(ctx context.Context, tuple platform.Tuple) (owner platform.Owner, err error) {
	start := time.Now()
	defer func() { o.measure(start, err) }()
	ctx, cancel := context.WithTimeout(ctx, 50*time.Millisecond)
	defer cancel()
	var after [2]time.Time
	primary := 0
	if tuple.Source.Addr().Is6() {
		primary = 1
	}
	for attempt := 0; attempt < 3; attempt++ {
		if attempt != 0 {
			o.tcpRetries.Add(1)
			select {
			case <-time.After(2 * time.Millisecond):
			case <-ctx.Done():
				return owner, ctx.Err()
			}
		}
		// Mapped IPv4 sockets may appear in the IPv6 table. Fall back there
		// after an IPv4 miss; an IPv6 tuple needs only the IPv6 table.
		for family := primary; family < 2; family++ {
			s, e := o.tcpSnapshot(ctx, after[family], family)
			if e != nil {
				if family == primary || ctx.Err() != nil {
					return owner, e
				}
				continue
			}
			candidates := s.rows.find(tuple)
			// Cached absence predating this socket is not a native lookup
			// miss. Refresh before spending one of the retry delays.
			if candidates.count == 0 && s.at.Before(start) {
				o.cacheMissRefreshes.Add(1)
				s, e = o.tcpSnapshot(ctx, s.at, family)
				if e != nil {
					if family == primary || ctx.Err() != nil {
						return owner, e
					}
					continue
				}
				candidates = s.rows.find(tuple)
			}
			if candidates.count > 1 {
				return owner, platform.ErrAmbiguous
			}
			if candidates.count == 1 {
				start := time.Now()
				defer measureStage(&o.processHist, start)
				return o.process(candidates.pid)
			}
			after[family] = s.at
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

func udpCandidate(key netip.AddrPort, rows map[netip.AddrPort][]socketOwner) (socketOwner, error) {
	candidates := rows[key]
	if len(candidates) == 0 {
		any := netip.IPv4Unspecified()
		if key.Addr().Is6() {
			any = netip.IPv6Unspecified()
		}
		candidates = rows[netip.AddrPortFrom(any, key.Port())]
	}
	if len(candidates) > 1 {
		return socketOwner{}, platform.ErrAmbiguous
	}
	if len(candidates) == 0 || candidates[0].created == 0 {
		return socketOwner{}, errOwnerMissing
	}
	return candidates[0], nil
}

func (o *Owners) udpOwner(key netip.AddrPort, rows map[netip.AddrPort][]socketOwner) (platform.Owner, error) {
	r, err := udpCandidate(key, rows)
	if err != nil {
		return platform.Owner{}, err
	}
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
	// A dump validates each process generation once. Opening the same process
	// handle for every one of its 4,096 sockets would consume the reconciliation
	// interval without adding any socket-generation evidence.
	type processResult struct {
		owner platform.Owner
		err   error
	}
	processes := make(map[uint32]processResult)
	for _, key := range keys {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		row, err := udpCandidate(key, rows)
		if err != nil {
			continue
		}
		result, ok := processes[row.pid]
		if !ok {
			result.owner, result.err = o.process(row.pid)
			processes[row.pid] = result
		}
		if result.err != nil {
			continue
		}
		owner := result.owner
		owner.Generation = strconv.FormatUint(row.created, 16)
		out[key] = owner
	}
	return out, nil
}
