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
	"github.com/AyoubAchour/net-switch/internal/winclock"
	"github.com/AyoubAchour/net-switch/internal/winhandle"
	"golang.org/x/sys/windows"
)

var iphlp = windows.NewLazySystemDLL("iphlpapi.dll")
var tcpTable = iphlp.NewProc("GetExtendedTcpTable")
var udpTable = iphlp.NewProc("GetExtendedUdpTable")
var errOwnerMissing = errors.New("socket owner not found")

// TCP_TABLE_OWNER_PID_CONNECTIONS: every state except LISTEN, so SYN_SENT is
// included. Filtering for ESTABLISHED loses the very sockets whose SYN is
// waiting for the engine's admission decision, and a listener never matches a
// SYN's 4-tuple. It is the cheapest class with owner PIDs (spec 5.6); the
// MODULE classes add per-row module data, and OWNER_PID_ALL (5) also walks
// the listener table. TestOwnerConnectionsClassKeepsSynSent checks both claims.
const tcpOwnerPIDConnections = 4
const tcpOwnerPIDAll = 5 // row counts in tests: every row the OS holds
const udpOwnerModule = 2

// The normal bound for one TCP owner lookup, and the overload hold (spec 5.6,
// "Under overload"): when a table read that started after the SYN arrived is
// still running at the normal bound, the SYN waits for that read, up to the
// hold in total, before its owner becomes unknown.
const ownerLookupBound = 50 * time.Millisecond
const ownerOverloadHold = 250 * time.Millisecond

type processKey struct {
	pid   uint32
	start uint64
}
type socketOwner struct {
	pid     uint32
	created uint64
}
type ownerSnapshot struct {
	at      time.Duration
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

type tcpRefresh = tableRead[*ownerSnapshot]

type LookupHistogram struct {
	Count     uint64 `json:"count"`
	Misses    uint64 `json:"misses"`
	Ambiguous uint64 `json:"ambiguous"`
	// Non-cumulative buckets, upper bounds in microseconds, last = infinity.
	UpperUS            []uint64        `json:"upperUS"`
	Buckets            []uint64        `json:"buckets"`
	MaxUS              uint64          `json:"maxUS"`
	TCPRefreshes       uint64          `json:"tcpRefreshes"`
	TCPReadNanos       uint64          `json:"tcpReadNanos"`
	TCPIndexNanos      uint64          `json:"tcpIndexNanos"`
	CacheMissRefreshes uint64          `json:"cacheMissRefreshes"`
	TCPRetries         uint64          `json:"tcpRetries"`
	SnapshotBuckets    []uint64        `json:"snapshotBuckets"`
	ProcessBuckets     []uint64        `json:"processBuckets"`
	RefreshBuckets     []uint64        `json:"refreshBuckets"`
	TCPRawRows         uint64          `json:"tcpRawRows"`
	TCPPeakRows        uint64          `json:"tcpPeakRows"`
	TCPRowsByFamily    [2]uint64       `json:"tcpRowsByFamily"`
	TCPFamiliesSampled [2]bool         `json:"tcpFamiliesSampled"`
	UDPRefreshes       uint64          `json:"udpRefreshes"`
	UDPReadNanos       uint64          `json:"udpReadNanos"`
	UDPIndexNanos      uint64          `json:"udpIndexNanos"`
	UDPReadBuckets     []uint64        `json:"udpReadBuckets"`    // native reads alone, not lookups
	UDPRefreshBuckets  []uint64        `json:"udpRefreshBuckets"` // slot start to published snapshot
	UDPWaitBuckets     []uint64        `json:"udpWaitBuckets"`    // a lookup's wait for one read
	UDPReadMaxUS       uint64          `json:"udpReadMaxUS"`      // slowest native read
	UDPPeakRows        uint64          `json:"udpPeakRows"`       // largest table read
	UDPParallelPeak    int             `json:"udpParallelPeak"`   // most reads in flight for one family
	TCPParallelPeak    int             `json:"tcpParallelPeak"`   // most reads in flight for one family
	TCPHolds           uint64          `json:"tcpHolds"`          // lookups held past 50 ms for a fresh read
	TCPHeldFound       uint64          `json:"tcpHeldFound"`      // held lookups that found the owner
	TCPReadMaxUS       uint64          `json:"tcpReadMaxUS"`      // slowest native TCP read
	TCPReadBuckets     []uint64        `json:"tcpReadBuckets"`    // native TCP reads alone, not lookups
	Failures           []lookupFailure `json:"failures,omitempty"`
}

var lookupBounds = [...]uint64{100, 250, 500, 1000, 2000, 3000, 4000, 5000, 10000, 20000, 50000, ^uint64(0)}

type Owners struct {
	mu                                                            sync.Mutex
	snapshot                                                      [2]atomic.Pointer[ownerSnapshot]
	tcpReads                                                      [2]tableReads[*ownerSnapshot]
	paths                                                         map[processKey]platform.Owner
	tcpBuffers                                                    [2][ownerParallelReads][]uint64
	udpSnapshots                                                  [2]atomic.Pointer[udpOwnerSnapshot]
	udpReads                                                      [2]tableReads[*udpOwnerSnapshot]
	udpBuffers                                                    [2][ownerParallelReads][]uint64
	udpDumps, udpReadNanos, udpIndexNanos                         atomic.Uint64
	udpReadHist, udpRefreshHist, udpWaitHist                      [len(lookupBounds)]atomic.Uint64
	udpReadMaxUS, udpPeakRows                                     atomic.Uint64
	hist                                                          [len(lookupBounds)]atomic.Uint64
	snapshotHist, processHist                                     [len(lookupBounds)]atomic.Uint64
	refreshHist                                                   [len(lookupBounds)]atomic.Uint64
	count, misses, ambiguous, maxUS                               atomic.Uint64
	tcpRefreshes, tcpReadNanos, tcpIndexNanos, cacheMissRefreshes atomic.Uint64
	tcpRetries                                                    atomic.Uint64
	tcpPeakRows                                                   atomic.Uint64
	tcpHolds, tcpHeldFound, tcpReadMaxUS                          atomic.Uint64
	tcpReadHist                                                   [len(lookupBounds)]atomic.Uint64
	failures                                                      [16]lookupFailure
	failureCount                                                  uint64
	// readTCP replaces the native TCP table read in tests; nil in production.
	readTCP func(ctx context.Context, family uint32, scratch *[]uint64) ([]byte, error)
}

func NewOwners() *Owners { return &Owners{paths: make(map[processKey]platform.Owner)} }

func measureStage(hist *[len(lookupBounds)]atomic.Uint64, start time.Duration) {
	us := uint64(max(0, winclock.Since(start).Microseconds()))
	for i, bound := range lookupBounds {
		if us <= bound {
			hist[i].Add(1)
			return
		}
	}
}

func (o *Owners) measure(start time.Duration, err error) {
	us := uint64(max(0, winclock.Since(start).Microseconds()))
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
	h.TCPHolds, h.TCPHeldFound, h.TCPReadMaxUS = o.tcpHolds.Load(), o.tcpHeldFound.Load(), o.tcpReadMaxUS.Load()
	h.TCPReadBuckets = make([]uint64, len(lookupBounds))
	for i := range h.TCPReadBuckets {
		h.TCPReadBuckets[i] = o.tcpReadHist[i].Load()
	}
	h.UDPRefreshes, h.UDPReadNanos, h.UDPIndexNanos = o.udpDumps.Load(), o.udpReadNanos.Load(), o.udpIndexNanos.Load()
	h.UDPReadBuckets = make([]uint64, len(lookupBounds))
	h.UDPRefreshBuckets = make([]uint64, len(lookupBounds))
	h.UDPWaitBuckets = make([]uint64, len(lookupBounds))
	for i := range h.UDPReadBuckets {
		h.UDPReadBuckets[i] = o.udpReadHist[i].Load()
		h.UDPRefreshBuckets[i] = o.udpRefreshHist[i].Load()
		h.UDPWaitBuckets[i] = o.udpWaitHist[i].Load()
	}
	h.UDPReadMaxUS, h.UDPPeakRows = o.udpReadMaxUS.Load(), o.udpPeakRows.Load()
	for family := range 2 {
		h.UDPParallelPeak = max(h.UDPParallelPeak, o.udpReads[family].peakInFlight())
		h.TCPParallelPeak = max(h.TCPParallelPeak, o.tcpReads[family].peakInFlight())
	}
	h.Failures = o.failureSnapshot()
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
	var scratch []uint64
	return readOwnerTableInto(ctx, proc, family, class, &scratch)
}

func readOwnerTableInto(ctx context.Context, proc *windows.LazyProc, family, class uint32, scratch *[]uint64) ([]byte, error) {
	size := uint32(max(32<<10, cap(*scratch)*8))
	for attempt := 0; attempt < 8; attempt++ {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if size < 4 || size > 64<<20 {
			return nil, errors.New("IP Helper table size outside budget")
		}
		if cap(*scratch)*8 < int(size) {
			*scratch = make([]uint64, (int(size)+7)/8)
		}
		// OWNER_MODULE rows contain 64-bit timestamps. Preserve their native
		// alignment explicitly, independently of a byte allocator's choices.
		b := unsafe.Slice((*byte)(unsafe.Pointer(&(*scratch)[0])), int(size))
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
// and at most ownerParallelReads staggered refreshes are shared by all SYNs of
// that family. A lookup never waits for the unrelated family's dump. Both
// waits remain cancellable.
func freshSnapshot(s *ownerSnapshot, after, now time.Duration) bool {
	return s != nil && s.at > after && now >= s.at && now-s.at < 5*time.Millisecond
}

// tcpSnapshot returns a snapshot of one family that started after `after`.
// normal ends at the lookup's 50 ms bound and ctx at the overload hold. When
// normal ends first, the wait continues only for a read that started after
// arrived (the SYN's arrival) and after `after`, and the result says it was
// held. holding means an earlier step already held, so normal no longer
// applies.
func (o *Owners) tcpSnapshot(ctx, normal context.Context, after, arrived time.Duration, family int, holding bool) (ownerSnapshot, bool, error) {
	start := winclock.Now()
	defer measureStage(&o.snapshotHist, start)
	run := func(r *tcpRefresh) { o.refreshTCP(r, family) }
	if holding {
		after = max(after, arrived-1) // reads at or after the arrival
	}
	for {
		if err := ctx.Err(); err != nil {
			return ownerSnapshot{}, holding, err
		}
		if s := o.snapshot[family].Load(); freshSnapshot(s, after, winclock.Now()) {
			return *s, holding, s.err
		}
		pending := o.tcpReads[family].join(after, run)
		bound := normal.Done()
		if holding {
			bound = nil
		}
	wait:
		for {
			select {
			case <-ctx.Done():
				return ownerSnapshot{}, holding, ctx.Err()
			case <-pending.done:
				break wait
			case <-bound:
				select {
				case <-pending.done:
					break wait // finished at the bound: no hold needed
				default:
				}
				// Spec 5.6, "Under overload". A read that started after the SYN
				// may already have finished while this lookup waited on an
				// older one; its snapshot serves without a hold.
				// Started after `after`, and at or after the arrival: a read
				// started in the same clock tick as the lookup still counts.
				threshold := max(after+1, arrived)
				if s := o.snapshot[family].Load(); s != nil && s.at >= threshold {
					return *s, holding, s.err
				}
				// A queued read counts: it starts only when a slot frees, so
				// after the SYN, and the hold's total still bounds the wait.
				fresh := o.tcpReads[family].since(threshold)
				if fresh == nil {
					return ownerSnapshot{}, holding, normal.Err()
				}
				o.tcpHolds.Add(1)
				pending, bound, holding, after = fresh, nil, true, threshold-1
			}
		}
		s := pending.result
		if s.at <= after {
			continue
		}
		return *s, holding, s.err
	}
}

func (o *Owners) refreshTCP(pending *tcpRefresh, family int) {
	// The IP Helper call is synchronous and cannot be cancelled. Keep at
	// most ownerParallelReads snapshots per family in flight, while every
	// lookup can leave at its own 50 ms deadline. One caller's cancellation
	// cannot poison peers.
	// The read's own deadline is the overload hold: a SYN held for this read
	// (spec 5.6) must not see it abandoned between sizing calls at 50 ms.
	ctx, cancel := winclock.System.WithTimeout(context.Background(), ownerOverloadHold)
	defer cancel()
	s := ownerSnapshot{at: pending.at}
	o.tcpRefreshes.Add(1)
	af, stride := uint32(windows.AF_INET), 24
	if family == 1 {
		af, stride = windows.AF_INET6, 56
	}
	readStart := winclock.Now()
	// Each slot owns its scratch buffer; the reads may overlap.
	var b []byte
	var err error
	if o.readTCP != nil {
		b, err = o.readTCP(ctx, af, &o.tcpBuffers[family][pending.slot])
	} else {
		b, err = readOwnerTableInto(ctx, tcpTable, af, tcpOwnerPIDConnections, &o.tcpBuffers[family][pending.slot])
	}
	readTook := winclock.Since(readStart)
	o.tcpReadNanos.Add(uint64(readTook))
	measureStage(&o.tcpReadHist, readStart)
	storeMax(&o.tcpReadMaxUS, uint64(max(0, readTook.Microseconds())))
	s.err = err
	if s.err == nil {
		indexStart := winclock.Now()
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
		o.tcpIndexNanos.Add(uint64(winclock.Since(indexStart)))
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
	// Reads may finish out of order; keep the newest-started snapshot.
	for current := o.snapshot[family].Load(); current == nil || current.at < s.at; current = o.snapshot[family].Load() {
		if o.snapshot[family].CompareAndSwap(current, &s) {
			break
		}
	}
	o.tcpReads[family].finish(pending, func(r *tcpRefresh) { o.refreshTCP(r, family) })
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
		return platform.Owner{}, fmt.Errorf("OpenProcess PID %d: %w", pid, err)
	}
	processOwner := winhandle.Open(h, "owner lookup process open")
	defer processOwner.HandleClose("owner lookup process close")
	var creation, exit, kernel, user windows.Filetime
	if err := windows.GetProcessTimes(processOwner.Handle("owner lookup creation time"), &creation, &exit, &kernel, &user); err != nil {
		return platform.Owner{}, fmt.Errorf("GetProcessTimes PID %d: %w", pid, err)
	}
	start := uint64(creation.HighDateTime)<<32 | uint64(creation.LowDateTime)
	key := processKey{pid, start}
	o.mu.Lock()
	cached := o.paths[key]
	o.mu.Unlock()
	if cached.Path == "" {
		b := make([]uint16, 32768)
		n := uint32(len(b))
		if err := windows.QueryFullProcessImageName(processOwner.Handle("owner lookup executable path"), 0, &b[0], &n); err != nil {
			return platform.Owner{}, fmt.Errorf("QueryFullProcessImageName PID %d: %w", pid, err)
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

// TCPLookupBound is how long the context the TCP forwarder passes must allow:
// the overload hold. TCP applies the normal 50 ms bound itself.
func (o *Owners) TCPLookupBound() time.Duration { return ownerOverloadHold }

func (o *Owners) TCP(ctx context.Context, tuple platform.Tuple) (owner platform.Owner, err error) {
	start := winclock.Now()
	// Where a failed lookup stopped, for the failure ring: at the OS port
	// limit (x64 run 39602903586) eleven misses sent SYNs to the default line.
	// Constant stages and plain fields, so a successful lookup pays nothing.
	var at struct {
		stage           string
		attempt, family int
		pid             uint32
	}
	at.stage = "start"
	defer func() {
		o.measure(start, err)
		if err != nil {
			o.noteFailure("tcp-lookup", fmt.Sprintf("%s (attempt %d, family %d, pid %d) after %d µs", at.stage, at.attempt,
				at.family, at.pid, winclock.Since(start).Microseconds()), tuple.Source, "", err)
		}
	}()
	// ctx bounds the overload hold; normal is the ordinary 50 ms bound. The
	// forwarder's context allows the hold (TCPLookupBound).
	ctx, cancel := winclock.System.WithTimeout(ctx, ownerOverloadHold)
	defer cancel()
	normal, cancelNormal := winclock.System.WithTimeout(ctx, ownerLookupBound)
	defer cancelNormal()
	held := false
	defer func() {
		if held {
			at.stage = "held: " + at.stage
			if err == nil {
				o.tcpHeldFound.Add(1)
			}
		}
	}()
	var after [2]time.Duration
	primary := 0
	if tuple.Source.Addr().Is6() {
		primary = 1
	}
	for attempt := 0; attempt < 3; attempt++ {
		at.stage, at.attempt = "bound check", attempt
		// Retries never run past the normal bound. A held lookup gets its
		// one fresh read per family, not more attempts.
		if winclock.Since(start) >= ownerLookupBound {
			if held {
				at.stage = "not in the held read"
				return owner, errOwnerMissing
			}
			return owner, context.DeadlineExceeded
		}
		if attempt != 0 {
			o.tcpRetries.Add(1)
			at.stage = "retry wait"
			if err := winclock.System.Wait(normal, 2*time.Millisecond); err != nil {
				return owner, err
			}
		}
		// Mapped IPv4 sockets may appear in the IPv6 table. Fall back there
		// after an IPv4 miss; an IPv6 tuple needs only the IPv6 table.
		for family := primary; family < 2; family++ {
			at.stage, at.family = "snapshot", family
			s, h, e := o.tcpSnapshot(ctx, normal, after[family], start, family, held)
			held = held || h
			if e != nil {
				if family == primary || ctx.Err() != nil || (!held && normal.Err() != nil) {
					return owner, e
				}
				continue
			}
			candidates := s.rows.find(tuple)
			// Cached absence predating this socket is not a native lookup
			// miss. Refresh before spending one of the retry delays, with a
			// read that started after this lookup began: the app's row exists
			// before its SYN reaches us, so that read contains it. A read
			// merely newer than the stale snapshot could still predate the
			// SYN and miss again (mixed corner on x64, 18b0d14: four SYNs ran
			// out of the 50 ms bound this way).
			if candidates.count == 0 && s.at < start {
				o.cacheMissRefreshes.Add(1)
				at.stage = "fresh read"
				var h bool
				s, h, e = o.tcpSnapshot(ctx, normal, max(s.at, start), start, family, held)
				held = held || h
				if e != nil {
					if family == primary || ctx.Err() != nil || (!held && normal.Err() != nil) {
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
				at.stage, at.pid = "process", candidates.pid
				processStart := winclock.Now()
				owner, err = o.process(candidates.pid)
				measureStage(&o.processHist, processStart)
				if elapsed := winclock.Since(start); elapsed >= ownerOverloadHold || elapsed >= ownerLookupBound && !held {
					return platform.Owner{}, context.DeadlineExceeded
				}
				if ctx.Err() != nil {
					return platform.Owner{}, ctx.Err()
				}
				return owner, err
			}
			after[family] = s.at
		}
	}
	at.stage = "not in any read"
	return owner, errOwnerMissing
}

func parseUDP(b []byte, v6 bool, rows *udpRows) error {
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
		rows.add(netip.AddrPortFrom(addr, port), socketOwner{pid, created})
	}
	return nil
}

func udpCandidate(key netip.AddrPort, rows udpRows) (socketOwner, error) {
	row := rows.find(key)
	if row.count == 0 {
		any := netip.IPv4Unspecified()
		if key.Addr().Is6() {
			any = netip.IPv6Unspecified()
		}
		row = rows.find(netip.AddrPortFrom(any, key.Port()))
	}
	if row.count > 1 {
		return socketOwner{}, platform.ErrAmbiguous
	}
	if row.count == 0 || row.owner.created == 0 {
		return socketOwner{}, errOwnerMissing
	}
	return row.owner, nil
}

func (o *Owners) udpOwner(key netip.AddrPort, rows udpRows) (platform.Owner, error) {
	r, err := udpCandidate(key, rows)
	if err != nil {
		return platform.Owner{}, err
	}
	owner, err := o.process(r.pid)
	owner.Generation = strconv.FormatUint(r.created, 16)
	return owner, err
}

func (o *Owners) UDP(ctx context.Context, key netip.AddrPort) (owner platform.Owner, err error) {
	start := winclock.Now()
	stage := "GetExtendedUdpTable snapshot"
	defer func() {
		o.measure(start, err)
		o.noteFailure("udp-lookup", stage, key, owner.Generation, err)
	}()
	ctx, cancel := winclock.System.WithTimeout(ctx, 50*time.Millisecond)
	defer cancel()
	family := 0
	if key.Addr().Is6() {
		family = 1
	}
	// Require a native read started after this call. Reusing an earlier
	// positive row would artificially lengthen the socket-generation collision
	// window. Concurrent calls still share the next in-flight native dump.
	snapshot, err := o.udpSnapshot(ctx, start, family)
	if err != nil {
		return owner, err
	}
	stage = "socket row and process identity"
	return o.udpOwner(key, snapshot.rows)
}

// The NAT invokes this once per second, even in the absence of traffic. One
// complete read per family covers every session. A partial read fails the whole
// validation; the NAT's two-second stale guard then stops both directions.
func (o *Owners) Snapshot(ctx context.Context, keys []netip.AddrPort) (result map[netip.AddrPort]platform.Owner, err error) {
	stage := "GetExtendedUdpTable reconciliation"
	defer func() {
		if err != nil {
			var source netip.AddrPort
			if len(keys) != 0 {
				source = keys[0]
			}
			o.noteFailure("udp-reconcile", stage, source, "", err)
		}
	}()
	rows := newUDPRows(len(keys), 0)
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
		if err := parseUDP(b, family == windows.AF_INET6, &rows); err != nil {
			return nil, err
		}
	}
	out := make(map[netip.AddrPort]platform.Owner, len(keys))
	stage = "reconciliation process identities"
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
			o.noteFailure("udp-reconcile-process", stage, key, "", result.err)
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
