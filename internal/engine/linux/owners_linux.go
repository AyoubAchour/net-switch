//go:build linux

package linux

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"hash/maphash"
	"io"
	"io/fs"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/AyoubAchour/net-switch/internal/apppath"
	"github.com/AyoubAchour/net-switch/internal/engine/platform"
	"golang.org/x/sys/unix"
)

type holder struct {
	pid   uint32
	start uint64
	fd    string
}

var errForcedUnknown = errors.New("acceptance: unknown owner")

type cachedHolders struct {
	holders  []holder
	observed time.Time
}
type fdWindow struct {
	start      uint64
	directory  uint64 // inode of the pinned kernel proc fd directory
	fdCount    int64  // descriptor count at the last complete pass; ordering hint only
	next       int64
	high       int64 // end of the sequentially indexed range; tail probes cannot advance it
	extent     int64 // largest descriptor observed, including tail probes
	lastFD     int64
	tailProbed bool
	observed   time.Time
	fullScan   time.Time // start of a completed, wholly indexed descriptor pass
	fullUID    uint32
	identity   *ownerValidation
}
type Owners struct {
	queries         diagPool
	batches         descriptorBatches
	warmed          bool
	lookupErrors    [4]atomic.Uint64
	cgroupStats     [3]atomic.Uint64
	sharedScans     atomic.Uint64
	metadataPasses  atomic.Uint64
	sharedMetadata  atomic.Uint64
	sharedScopes    atomic.Uint64
	holderTimeouts  atomic.Uint64
	timeoutPhases   [lookupPhases]lookupPhaseCounter
	lastLookupError atomic.Pointer[string]
	mu              sync.Mutex
	cgroupMu        sync.RWMutex
	recentMu        sync.RWMutex
	cgroups         map[uint64]string
	scopeReads      [64]atomic.Pointer[scopePIDSnapshot]
	recent          map[uint32]*recentOwners
	index           [ownerIndexShards]ownerIndex
	indexSeed       maphash.Seed
	windows         map[uint32]fdWindow
	ambiguousPorts  map[uint16]time.Time
	// Fault callbacks are assigned only by the acceptance build.
	fault        func(context.Context) error
	destroyFault func(context.Context, socketRow, func())
}

type lookupStats struct {
	Timeout, Missing, Ambiguous, Other                                                   uint64
	CgroupHints, CgroupResolved, CgroupPopulated                                         uint64
	LastError                                                                            string
	MetadataRejected                                                                     uint64
	LastMetadataError                                                                    string
	SharedScans                                                                          uint64
	MetadataPasses, SharedMetadata                                                       uint64
	SharedScopes                                                                         uint64
	HolderTimeouts                                                                       uint64
	TimeoutStages                                                                        map[string]lookupPhaseStat
	DescriptorBatches, SharedBatches, EarlyBatchHints                                    uint64
	BatchDescriptors, BatchSockets, BatchQueueFull, AbortedBatches                       uint64
	BatchQueueNanos, BatchServiceNanos, BatchMaxQueueNanos, BatchMaxServiceNanos         uint64
	ReusedBatches, StaleBatchRetries, ConflictBatchRequests                              uint64
	InlineBatches                                                                        uint64
	BatchCompletionNanos, BatchResumeNanos, BatchMaxCompletionNanos, BatchMaxResumeNanos uint64
	BatchLockNanos, BatchUnlockNanos, BatchMaxLockNanos, BatchMaxUnlockNanos uint64
}

func (o *Owners) Stats() any {
	s := lookupStats{Timeout: o.lookupErrors[0].Load(), Missing: o.lookupErrors[1].Load(), Ambiguous: o.lookupErrors[2].Load(), Other: o.lookupErrors[3].Load()}
	s.CgroupHints, s.CgroupResolved, s.CgroupPopulated = o.cgroupStats[0].Load(), o.cgroupStats[1].Load(), o.cgroupStats[2].Load()
	s.MetadataRejected = rejectedMetadata.Load()
	s.SharedScans = o.sharedScans.Load()
	s.MetadataPasses, s.SharedMetadata = o.metadataPasses.Load(), o.sharedMetadata.Load()
	s.SharedScopes = o.sharedScopes.Load()
	s.DescriptorBatches, s.SharedBatches, s.EarlyBatchHints = o.batches.started.Load(), o.batches.shared.Load(), o.batches.early.Load()
	s.BatchDescriptors, s.BatchSockets = o.batches.fds.Load(), o.batches.sockets.Load()
	s.BatchQueueFull, s.AbortedBatches = o.batches.full.Load(), o.batches.aborted.Load()
	s.BatchQueueNanos, s.BatchServiceNanos = o.batches.queueNanos.Load(), o.batches.serviceNanos.Load()
	s.ReusedBatches, s.StaleBatchRetries, s.ConflictBatchRequests = o.batches.reused.Load(), o.batches.staleRetries.Load(), o.batches.conflictWaits.Load()
	s.InlineBatches = o.batches.inline.Load()
	s.BatchCompletionNanos, s.BatchResumeNanos = o.batches.completionNanos.Load(), o.batches.resumeNanos.Load()
	s.BatchMaxCompletionNanos, s.BatchMaxResumeNanos = o.batches.maxCompletion.Load(), o.batches.maxResume.Load()
	s.BatchLockNanos, s.BatchUnlockNanos = o.batches.lockNanos.Load(), o.batches.unlockNanos.Load()
	s.BatchMaxLockNanos, s.BatchMaxUnlockNanos = o.batches.maxLock.Load(), o.batches.maxUnlock.Load()
	s.BatchMaxQueueNanos, s.BatchMaxServiceNanos = o.batches.maxQueue.Load(), o.batches.maxService.Load()
	s.HolderTimeouts = o.holderTimeouts.Load()
	for phase := range o.timeoutPhases {
		counter := &o.timeoutPhases[phase]
		if count := counter.count.Load(); count != 0 {
			if s.TimeoutStages == nil {
				s.TimeoutStages = make(map[string]lookupPhaseStat)
			}
			s.TimeoutStages[lookupPhaseNames[phase]] = lookupPhaseStat{Count: count, Largest: counter.largest.Load(), TotalNanos: counter.total.Load(), MaxNanos: counter.maximum.Load()}
		}
	}
	if p := lastRejectedMetadata.Load(); p != nil {
		s.LastMetadataError = *p
	}
	if p := o.lastLookupError.Load(); p != nil {
		s.LastError = *p
	}
	return s
}
func (o *Owners) recordError(err error) {
	if err == nil {
		return
	}
	i := 3
	switch {
	case errors.Is(err, context.DeadlineExceeded) || errors.Is(err, os.ErrDeadlineExceeded):
		i = 0
	case errors.Is(err, os.ErrNotExist) || errors.Is(err, unix.ENOENT):
		i = 1
	case errors.Is(err, platform.ErrAmbiguous):
		i = 2
	}
	o.lookupErrors[i].Add(1)
	text := err.Error()
	if len(text) > 512 {
		text = text[:512]
	}
	o.lastLookupError.Store(&text)
}

// Load the kernel's diagnostic handlers and the cgroup directory index before
// capture. No socket owner is cached here: every admitted socket is still cold.
func (o *Owners) Warm(ctx context.Context) error {
	o.mu.Lock()
	ready := o.warmed
	o.mu.Unlock()
	if ready {
		return nil
	}
	for _, family := range []int{unix.AF_INET, unix.AF_INET6} {
		for _, protocol := range []int{unix.IPPROTO_TCP, unix.IPPROTO_UDP} {
			address := netip.IPv4Unspecified()
			if family == unix.AF_INET6 {
				address = netip.IPv6Unspecified()
			}
			endpoint := netip.AddrPortFrom(address, 65535)
			if _, err := o.query(ctx, family, protocol, endpoint, endpoint); err != nil && !errors.Is(err, unix.ENOENT) {
				return fmt.Errorf("initialize socket diagnostics: %w", err)
			}
		}
	}
	_ = o.refreshCgroups(ctx)
	if err := ctx.Err(); err != nil {
		return err
	}
	o.mu.Lock()
	o.warmed = true
	o.mu.Unlock()
	return nil
}

func NewOwners() *Owners {
	// Inode hints and their subscribers share a shard, not the process-state
	// lock. Small workloads need not retain and scan tens of MiB of empty
	// index space, and a growing shard cannot stall every other lookup.
	o := &Owners{cgroups: make(map[uint64]string, 256), recent: make(map[uint32]*recentOwners, 64), windows: make(map[uint32]fdWindow, 256), ambiguousPorts: map[uint16]time.Time{}, indexSeed: maphash.MakeSeed()}
	for i := range o.index {
		o.index[i].inodes = make(map[uint32]inodeHolders, 16)
		o.index[i].waiters = make(map[uint32]*inodeWaiter, 16)
	}
	return o
}

func (o *Owners) Close() {
	o.closeDescriptorBatches()
	o.queries.close()
}
func (o *Owners) query(ctx context.Context, family, protocol int, local, remote netip.AddrPort) ([]socketRow, error) {
	return diagQuery(ctx, family, protocol, local, remote, false, &o.queries)
}

// Work stops short of 10 ms to leave room for returning, timing and policy
// admission. The caller's earlier cancellation always wins.
func lookupContext(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(ctx, 8*time.Millisecond)
}
func (o *Owners) TCP(ctx context.Context, t platform.Tuple) (owner platform.Owner, err error) {
	defer func() { o.recordError(err) }()
	if o.fault != nil {
		if err := o.fault(ctx); err != nil {
			return platform.Owner{}, err
		}
	}
	ctx, cancel := lookupContext(ctx)
	defer cancel()
	queryStarted := time.Now()
	rows, err := o.query(ctx, familyOf(t.Source.Addr()), unix.IPPROTO_TCP, t.Source, t.Destination)
	if errors.Is(err, unix.ENOENT) && t.Source.Addr().Is4() {
		rows, err = o.query(ctx, unix.AF_INET6, unix.IPPROTO_TCP, t.Source, t.Destination)
	}
	if errors.Is(err, unix.ENOENT) {
		rows, err = diagDump(ctx, familyOf(t.Source.Addr()), unix.IPPROTO_TCP, t.Source)
	}
	if err != nil {
		return platform.Owner{}, fmt.Errorf("TCP socket query: %w", err)
	}
	queryTime := time.Since(queryStarted)
	for _, r := range rows {
		if r.local == t.Source && r.remote == t.Destination {
			owner, err = o.holders(ctx, r)
			if err != nil {
				err = fmt.Errorf("TCP holder scan: %w (socket query %s)", err, queryTime)
			}
			return owner, err
		}
	}
	return platform.Owner{}, os.ErrNotExist
}
func (o *Owners) UDP(ctx context.Context, source netip.AddrPort) (platform.Owner, error) {
	return o.udpOwner(ctx, platform.Tuple{Source: source})
}
func (o *Owners) UDPFor(ctx context.Context, tuple platform.Tuple) (platform.Owner, error) {
	return o.udpOwner(ctx, tuple)
}
func (o *Owners) udpOwner(ctx context.Context, tuple platform.Tuple) (owner platform.Owner, err error) {
	source := tuple.Source
	defer func() { o.recordError(err) }()
	unknown := false
	if o.fault != nil {
		if err := o.fault(ctx); err != nil {
			if !errors.Is(err, errForcedUnknown) {
				return platform.Owner{}, err
			}
			unknown = true
		}
	}
	ctx, cancel := lookupContext(ctx)
	defer cancel()
	// Exact lookup is useful for the common wildcard socket. A port-filtered
	// dump also detects SO_REUSEPORT ambiguity instead of accepting the arbitrary
	// socket that the kernel's inbound hash selected.
	exact, err := o.query(ctx, familyOf(source.Addr()), unix.IPPROTO_UDP, source, tuple.Destination)
	if err != nil && !errors.Is(err, unix.ENOENT) {
		return platform.Owner{}, fmt.Errorf("UDP exact query: %w", err)
	}
	o.mu.Lock()
	ambiguous := time.Now().Before(o.ambiguousPorts[source.Port()])
	if !ambiguous {
		delete(o.ambiguousPorts, source.Port())
	}
	o.mu.Unlock()
	if err == nil && tuple.Destination.IsValid() && !ambiguous {
		if r, e := matchUDP(exact, source); e == nil {
			return o.resolveUDP(ctx, r, unknown)
		}
	}
	rows, err := diagDump(ctx, familyOf(source.Addr()), unix.IPPROTO_UDP, source)
	if err != nil {
		return platform.Owner{}, fmt.Errorf("UDP family dump: %w", err)
	}
	if source.Addr().Is4() {
		v6, err := diagDump(ctx, unix.AF_INET6, unix.IPPROTO_UDP, source)
		if err != nil {
			return platform.Owner{}, fmt.Errorf("UDP dual-stack dump: %w", err)
		}
		rows = append(rows, v6...)
	}
	r, err := matchUDP(rows, source)
	if errors.Is(err, errSocketAmbiguous) {
		o.mu.Lock()
		o.ambiguousPorts[source.Port()] = time.Now().Add(2 * time.Second)
		o.mu.Unlock()
		return platform.Owner{Generation: cookieSet(rows, source)}, platform.ErrAmbiguous
	}
	if err != nil {
		return platform.Owner{}, err
	}
	return o.resolveUDP(ctx, r, unknown)
}

func (o *Owners) resolveUDP(ctx context.Context, r socketRow, unknown bool) (owner platform.Owner, err error) {
	if unknown {
		return platform.Owner{Generation: r.generation()}, nil
	}
	owner, err = o.holders(ctx, r)
	if err != nil {
		owner = platform.Owner{Generation: r.generation()}
		err = fmt.Errorf("UDP holder scan: %w", err)
	}
	return owner, err
}

func processStart(pid uint32) (uint64, error) {
	storage := processBuffers.Get()
	defer processBuffers.Put(storage)
	b, err := readInto(fmt.Sprintf("/proc/%d/stat", pid), storage[:4096])
	if err != nil {
		return 0, err
	}
	return parseProcessStart(b)
}

func parseProcessStart(b []byte) (uint64, error) {
	end := bytes.LastIndexByte(b, ')')
	if end < 0 {
		return 0, errors.New("bad process stat")
	}
	// Field 22 is the twentieth token after the parenthesized comm. Parsing
	// just this field avoids allocating a string and slice for every field.
	position := end + 1
	for field := 0; field < 20; field++ {
		for position < len(b) && (b[position] == ' ' || b[position] == '\t' || b[position] == '\n') {
			position++
		}
		start := position
		for position < len(b) && b[position] != ' ' && b[position] != '\t' && b[position] != '\n' {
			position++
		}
		if start == position {
			return 0, errors.New("short process stat")
		}
		if field == 19 {
			return strconv.ParseUint(string(b[start:position]), 10, 64)
		}
	}
	return 0, errors.New("short process stat")
}
func processOwner(pid uint32) (platform.Owner, error) {
	start, err := processStart(pid)
	if err != nil {
		return platform.Owner{}, err
	}
	return processOwnerAt(pid, start)
}

// The caller supplies the incarnation from its descriptor scan or cache hint.
// Verify it after reading metadata and before returning any usable identity.
func processOwnerAt(pid uint32, start uint64) (platform.Owner, error) {
	root := fmt.Sprintf("/proc/%d/", pid)
	exe, err := readProcLink(root + "exe")
	if err != nil {
		return platform.Owner{}, err
	}
	exe = strings.TrimSuffix(exe, " (deleted)")
	id := apppath.Normalize(exe, apppath.Linux)
	storage := processBuffers.Get()
	// Flatpak's mount namespace metadata identifies apps that have identical
	// /app/bin executable paths. It belongs to the holder, never to the socket.
	// Native apps have no metadata file. Do not borrow 64 KiB for every
	// concurrent lookup just to receive ENOENT; the small scratch also covers
	// normal Flatpak headers. Only a header beyond it needs the larger bound.
	info, infoErr := readFlatpakInfo(root+"root", storage[:])
	var flatpak *[64 << 10]byte
	if errors.Is(infoErr, errKernelFileLimit) {
		flatpak = flatpakBuffers.Get()
		info, infoErr = readFlatpakInfo(root+"root", flatpak[:])
	}
	if infoErr != nil && !errors.Is(infoErr, unix.ENOENT) && !errors.Is(infoErr, unix.ESRCH) {
		rejectedMetadata.Add(1)
		message := fmt.Sprintf("pid %d Flatpak metadata rejected: %v", pid, infoErr)
		lastRejectedMetadata.Store(&message)
	}
	if b, err := info, infoErr; err == nil {
		section := ""
		for _, line := range strings.Split(string(b), "\n") {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "[") {
				section = line
			}
			if section == "[Application]" && strings.HasPrefix(line, "name=") {
				id = "flatpak:" + strings.TrimPrefix(line, "name=")
				break
			}
		}
	} else if strings.HasPrefix(exe, "/snap/") {
		parts := strings.Split(exe, "/")
		if len(parts) > 3 {
			id = "snap:" + parts[2]
		}
	} else {
		b, err := readInto(root+"environ", storage[:])
		if errors.Is(err, errKernelFileLimit) {
			b, err = readKernelFile(root+"environ", 8<<20)
		}
		for err == nil && len(b) > 0 {
			v, rest, _ := bytes.Cut(b, []byte{0})
			b = rest
			if bytes.HasPrefix(v, []byte("APPIMAGE=")) {
				name := filepath.Base(string(v[len("APPIMAGE="):]))
				if strings.HasSuffix(strings.ToLower(name), ".appimage") {
					id = "appimage:" + name[:len(name)-9]
				}
				break
			}
		}
	}
	if flatpak != nil {
		flatpakBuffers.Put(flatpak)
	}
	processBuffers.Put(storage)
	end, err := processStart(pid)
	if err != nil || end != start {
		return platform.Owner{}, os.ErrNotExist
	}
	return platform.Owner{PID: pid, StartTime: start, Path: exe, AppID: id}, nil
}

type scopePIDSnapshot struct {
	id    uint64
	began time.Time
	pids  []uint32
}

func (o *Owners) cgroupPIDs(ctx context.Context, id uint64, requested time.Time) []uint32 {
	return o.cgroupPIDsTimed(ctx, id, requested, nil)
}

func (o *Owners) cgroupPIDsTimed(ctx context.Context, id uint64, requested time.Time, timing *lookupTiming) []uint32 {
	if id == 0 || ctx.Err() != nil {
		return nil
	}
	o.cgroupStats[0].Add(1)
	cache := &o.scopeReads[maphash.Comparable(o.indexSeed, id)%uint64(len(o.scopeReads))]
	if previous := cache.Load(); previous != nil && previous.id == id && !previous.began.Before(requested) {
		o.cgroupStats[1].Add(1)
		if len(previous.pids) > 0 {
			o.cgroupStats[2].Add(1)
		}
		o.sharedScopes.Add(1)
		return previous.pids
	}
	started := time.Now()
	o.cgroupMu.RLock()
	dir := o.cgroups[id]
	o.cgroupMu.RUnlock()
	if dir == "" {
		_ = o.refreshCgroups(ctx)
		o.cgroupMu.RLock()
		dir = o.cgroups[id]
		o.cgroupMu.RUnlock()
	}
	timing.add(phaseScopeMap, time.Since(started))
	if dir == "" {
		return nil
	}
	o.cgroupStats[1].Add(1)
	began := time.Now()
	storage := processBuffers.Get()
	timing.add(phaseScopeScratch, time.Since(began))
	defer func() {
		started := time.Now()
		processBuffers.Put(storage)
		timing.add(phaseScopeScratch, time.Since(started))
	}()
	path := filepath.Join(dir, "cgroup.procs")
	b, err := readScopeInto(path, storage[:], timing)
	if errors.Is(err, errKernelFileLimit) {
		started = time.Now()
		b, err = readKernelFile(path, 1<<20)
		timing.add(phaseScopeRead, time.Since(started))
	}
	if err != nil {
		return nil
	}
	started = time.Now()
	pids := make([]uint32, 0, 32)
	for len(b) > 0 {
		line, rest, _ := bytes.Cut(b, []byte{'\n'})
		b = rest
		v, e := strconv.ParseUint(string(bytes.TrimSpace(line)), 10, 32)
		if e == nil {
			pids = append(pids, uint32(v))
		}
	}
	slices.Sort(pids)
	slices.Reverse(pids)
	if len(pids) > 0 {
		o.cgroupStats[2].Add(1)
	}
	// This is an immutable search hint read during this operation, not a
	// membership TTL. No request that began after the read may reuse it.
	cache.Store(&scopePIDSnapshot{id: id, began: began, pids: pids})
	timing.add(phaseScopeParse, time.Since(started))
	return pids
}

func (o *Owners) refreshCgroups(ctx context.Context) error {
	found := map[uint64]string{}
	err := filepath.WalkDir("/sys/fs/cgroup", func(path string, e fs.DirEntry, err error) error {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if err != nil {
			return fs.SkipDir
		}
		if !e.IsDir() {
			return nil
		}
		var st unix.Stat_t
		if unix.Stat(path, &st) == nil {
			found[st.Ino] = path
		}
		return nil
	})
	o.cgroupMu.Lock()
	if len(o.cgroups) > 8192 {
		clear(o.cgroups)
	}
	for id, path := range found {
		o.cgroups[id] = path
	}
	o.cgroupMu.Unlock()
	return err
}

func (o *Owners) holders(ctx context.Context, r socketRow) (owner platform.Owner, lookupErr error) {
	if r.inode == 0 {
		return platform.Owner{}, os.ErrNotExist
	}
	requested := time.Now()
	var timing lookupTiming
	defer func() {
		if errors.Is(lookupErr, context.DeadlineExceeded) {
			o.recordHolderTimeout(timing, time.Since(requested))
		}
	}()
	deadline, timed := ctx.Deadline()
	expired := func() bool { return ctx.Err() != nil || (timed && !time.Now().Before(deadline)) }
	if expired() {
		return platform.Owner{}, context.DeadlineExceeded
	}
	var result platform.Owner
	var found []holder
	var validationTime, initialIndexTime, scopeTime time.Duration
	var scannedPIDs, scannedFDs, hinted int
	var lastPID, lastUID uint32
	var lastIndexed bool
	var lastPosition int64
	seen := map[uint32]bool{}
	accept := func(h holder) error {
		if expired() {
			return nil
		}
		for _, previous := range found {
			if previous == h {
				return nil
			}
		}
		validationStarted := time.Now()
		defer func() {
			elapsed := time.Since(validationStarted)
			validationTime += elapsed
			timing.add(phaseValidation, elapsed)
		}()
		path := fmt.Sprintf("/proc/%d/fd/%s", h.pid, h.fd)
		got, ok := socketInodeAt(unix.AT_FDCWD, path)
		if !ok || got != r.inode {
			return nil
		}
		// A shared metadata read must begin after this descriptor check.
		// Check the descriptor again afterward, before accepting the holder.
		checked := time.Now()
		live, err := o.validationFor(h).resolve(ctx, checked, o)
		if err != nil || live.StartTime != h.start {
			if errors.Is(err, os.ErrNotExist) {
				o.invalidateStart(h)
			}
			return nil
		}
		if got, ok := socketInodeAt(unix.AT_FDCWD, path); !ok || got != r.inode {
			return nil
		}
		if result.AppID != "" && result.AppID != live.AppID {
			return platform.ErrAmbiguous
		}
		if result.AppID == "" {
			result = live
		}
		found = append(found, h)
		seen[h.pid] = true
		if fd, err := strconv.ParseInt(h.fd, 10, 64); err == nil {
			o.mu.Lock()
			window := o.windows[h.pid]
			if window.start != h.start {
				window = fdWindow{start: h.start, lastFD: -1}
			}
			window.lastFD = fd
			window.extent = max(window.extent, fd)
			window.observed = time.Now()
			o.windows[h.pid] = window
			o.mu.Unlock()
		}
		return nil
	}
	hasHolder := func(pid uint32) bool {
		for _, h := range found {
			if h.pid == pid {
				return true
			}
		}
		return false
	}
	indexStarted := time.Now()
	var cached []holder
	if r.protocol == unix.IPPROTO_UDP {
		cached = o.cachedHolders(r.cookie)
	}
	recent := o.recentPIDs(r.uid)
	indexed := o.indexed(r.inode)
	initialIndexTime = time.Since(indexStarted)
	timing.add(phaseIndex, initialIndexTime)
	hinted += len(cached) + indexed.count()
	for _, h := range cached {
		if err := accept(h); err != nil {
			return platform.Owner{}, err
		}
	}
	if err := indexed.visit(accept); err != nil {
		return platform.Owner{}, err
	}
	var notice *inodeWaiter
	if result.AppID == "" {
		notice = o.subscribe(r.inode)
		defer func() { o.unsubscribe(r.inode, notice) }()
	}
	checkHints := func() error {
		if result.AppID != "" || expired() {
			return nil
		}
		hints := o.indexed(r.inode)
		hinted += hints.count()
		if err := hints.visit(accept); err != nil {
			return err
		}
		if result.AppID == "" && notice != nil {
			select {
			case <-notice.ready:
				o.unsubscribe(r.inode, notice)
				notice = o.subscribe(r.inode)
				return o.indexed(r.inode).visit(accept)
			default:
			}
		}
		return nil
	}

	// /proc's fd directory is seekable: its position is fd+2 (fs/proc/fd.c).
	// Concurrent cold lookups share small rotating windows and index sockets
	// seen along the way. The index is only a hint; accept rechecks the live fd
	// and PID start time on every use. Regular files never enter the index.
	var heavy []uint32
	scan := func(pid uint32, complete bool) (scanErr error) {
		if err := checkHints(); err != nil {
			return err
		}
		if seen[pid] || expired() {
			return nil
		}
		seen[pid] = true
		scannedPIDs++
		if !complete && result.AppID != "" {
			o.mu.Lock()
			observed := o.windows[pid].observed
			o.mu.Unlock()
			if time.Since(observed) < 5*time.Millisecond {
				return nil
			}
		}
		dir := fmt.Sprintf("/proc/%d/fd", pid)
		opened := time.Now()
		f, err := openProcDescriptors(dir)
		if err != nil {
			timing.add(phaseProcessOpen, time.Since(opened))
			return nil
		}
		closeDirectory := func() {
			started := time.Now()
			f.Close()
			timing.add(phaseProcessClose, time.Since(started))
		}
		defer closeDirectory()
		descriptor := f.fd
		var metadata unix.Stat_t
		statErr := unix.Fstat(descriptor, &metadata)
		timing.add(phaseProcessOpen, time.Since(opened))
		if statErr != nil {
			return nil
		}
		canIndex := metadata.Uid == r.uid || slices.Contains(recent, pid)
		lastPID, lastUID, lastIndexed = pid, metadata.Uid, canIndex
		if expired() {
			return nil
		}
		if err := checkHints(); err != nil {
			return err
		}
		if hasHolder(pid) {
			return nil
		}
		var start uint64
		o.mu.Lock()
		previous := o.windows[pid]
		if previous.directory == metadata.Ino {
			start = previous.start
		}
		o.mu.Unlock()
		if start == 0 {
			started := time.Now()
			start, err = processStart(pid)
			timing.add(phaseProcessStart, time.Since(started))
			if err != nil || expired() {
				return nil
			}
		}
		o.mu.Lock()
		if len(o.windows) > 4096 {
			for old := range o.windows {
				if old != pid {
					delete(o.windows, old)
				}
				if len(o.windows) <= 4096 {
					break
				}
			}
		}
		current := o.windows[pid]
		if current.directory != metadata.Ino || (current.start != 0 && current.start != start) {
			current = fdWindow{directory: metadata.Ino, start: start, lastFD: -1}
		}
		if current.fullUID == r.uid && !current.fullScan.Before(requested) {
			o.mu.Unlock()
			o.sharedScans.Add(1)
			return o.indexed(r.inode).visit(accept)
		}
		current.start = start
		window := current
		current.next += 64
		o.windows[pid] = current
		o.mu.Unlock()
		// Shared descriptor jobs now serialize identical work. A caller's
		// scheduling or metadata reads must not hold a separate PID gate.
		var batchErr error
		defer func() {
			if scanErr == nil && batchErr != nil {
				scanErr = batchErr
			}
			if scanErr == nil && !expired() {
				scanErr = o.indexed(r.inode).visit(accept)
			}
		}()
		defer closeDirectory()
		position := window.next
		lastPosition = window.high
		if position > 0 {
			if _, err := f.Seek(position, 0); err != nil {
				return nil
			}
		}
		maxFD := window.high
		maxSeen := window.extent
		remember := make(map[uint32]holder, 32)
		advancing := false
		whole := false
		matched := false
		visit := func(fd []byte) bool {
			if expired() {
				return false
			}
			scannedFDs++
			if number, err := strconv.ParseInt(string(fd), 10, 64); err == nil {
				maxSeen = max(maxSeen, number)
				if advancing {
					maxFD = max(maxFD, number)
				}
			}
			inode, ok := socketInodeAt(descriptor, string(fd))
			if !ok {
				return true
			}
			if canIndex || uint32(inode) == r.inode {
				remember[uint32(inode)] = holder{pid, start, string(fd)}
				if len(remember) >= 32 {
					o.publish(remember)
					clear(remember)
				}
			}
			if uint32(inode) == r.inode {
				matched = true
				// Publish and release this PID's scanner before validating the
				// owner. Reading the rest of a large window after finding our
				// socket can spend its remaining deadline on unrelated FDs.
				return false
			}
			return true
		}
		visitFDs := func(limit int) (int, error) {
			started := time.Now()
			defer func() { timing.add(phaseDescriptors, time.Since(started)) }()
			offset, err := f.Seek(0, io.SeekCurrent)
			if err != nil {
				return 0, err
			}
			key := descriptorBatchKey{pid: pid, uid: r.uid, start: start, directory: metadata.Ino, offset: offset, limit: limit, advance: advancing, cacheAll: canIndex}
		acquire:
			for !expired() {
				job, err := o.descriptorBatch(ctx, key, requested, result.AppID != "")
				if err != nil {
					var busy *descriptorQueueBusy
					if errors.As(err, &busy) {
						select {
						case <-busy.ready:
							continue
						case <-ctx.Done():
							err = ctx.Err()
						}
					}
					batchErr = err
					return 0, err
				}
				if result.AppID != "" {
					o.batches.conflictWaits.Add(1)
				}
				waiting := time.Now()
				for {
					var ready <-chan struct{}
					if notice != nil && result.AppID == "" {
						ready = notice.ready
					}
					select {
					case <-ready:
						inThisPID := func() bool {
							found := false
							o.indexed(r.inode).visit(func(h holder) error {
								found = found || (h.pid == pid && h.start == start)
								return nil
							})
							return found
						}
						if !inThisPID() {
							// Another holder's hint cannot finish this PID's search.
							// Subscribe again, then close the publication race.
							o.unsubscribe(r.inode, notice)
							notice = o.subscribe(r.inode)
							if !inThisPID() {
								continue
							}
						}
						matched = true
						select {
						case <-job.done:
						default:
							o.batches.early.Add(1)
						}
						return 0, nil
					case <-job.done:
						o.batches.resumed(job, waiting)
						out := job.result
						scannedFDs += out.count
						maxSeen = max(maxSeen, out.lastFD)
						if advancing {
							maxFD = max(maxFD, out.lastFD)
						}
						for _, socket := range out.sockets {
							if socket.inode == r.inode {
								// A foreign-process scan may have read this inode before
								// our subscription. Publish its exact FD, then use the
								// same live identity validation as every other hint.
								o.publish(map[uint32]holder{r.inode: {pid: pid, start: start, fd: strconv.FormatInt(socket.fd, 10)}})
								matched = true
								break
							}
						}
						if !matched && errors.Is(out.err, context.DeadlineExceeded) {
							continue acquire
						}
						// A window begun before this request can supply a live
						// positive hint, but a miss needs a fresh pass. Newly
						// created descriptors may be absent from its kernel buffer.
						if !matched && out.began.Before(requested) {
							o.batches.staleRetries.Add(1)
							continue acquire
						}
						if out.began.Before(requested) && errors.Is(out.err, io.EOF) {
							return out.count, nil
						}
						return out.count, out.err
					case <-ctx.Done():
						select {
						case <-job.done:
							o.batches.resumed(job, waiting)
						default:
						}
						batchErr = ctx.Err()
						return 0, ctx.Err()
					}
				}
			}
			batchErr = context.DeadlineExceeded
			return 0, context.DeadlineExceeded
		}
		defer func() {
			o.publish(remember)
			o.mu.Lock()
			defer o.mu.Unlock()
			if current := o.windows[pid]; current.directory == metadata.Ino {
				current.high = max(current.high, maxFD)
				current.extent = max(current.extent, maxSeen)
				current.observed = time.Now()
				o.windows[pid] = current
			}
		}()
		recentRange := func() error {
			// A burst of refused connections closes and reuses descriptors
			// below the high-water mark. Inspect that recent range before a
			// full fallback walk; a lone lastFD hint misses concurrent holes.
			end := window.extent
			if _, err := f.Seek(max(0, end-1023)+2, 0); err == nil {
				_, _ = visitFDs(1024)
			}
			return nil
		}
		if complete && canIndex && window.extent >= 128 {
			if err := recentRange(); err != nil {
				return err
			}
			if matched {
				return nil
			}
		}
		if !complete {
			// Small descriptor sets are commonly reused by concurrent short
			// connections. The last descriptor alone misses its neighbours.
			if window.extent < 128 || (window.lastFD >= 0 && window.lastFD < 128) {
				if _, err := f.Seek(0, 0); err == nil {
					advancing = true
					_, readErr := visitFDs(128)
					advancing = false
					whole = errors.Is(readErr, io.EOF) && !expired()
					if whole {
						return nil
					}
					if matched {
						return nil
					}
				}
			}
			// Reopening normally reuses the previous descriptor. Check that
			// one live link even when another lookup just scanned this process.
			if window.lastFD >= 0 {
				visit([]byte(strconv.FormatInt(window.lastFD, 10)))
				if matched {
					return nil
				}
			}
			// Scan newly allocated descriptors first. Everything below this
			// high-water mark was already indexed by a prior window; rescanning
			// 256 neighbours in every unrelated process made multi-app bursts
			// spend their entire lookup budget reading the same symlinks.
			if _, err := f.Seek(maxFD+3, 0); err == nil {
				count := 128
				if canIndex {
					count = 512
				}
				advancing = true
				_, _ = visitFDs(count)
				advancing = false
				if matched {
					return nil
				}
			}
			if canIndex && window.extent >= 128 && len(recent) > 0 && recent[0] == pid {
				if err := recentRange(); err != nil {
					return err
				}
				if matched {
					return nil
				}
			}
			if time.Since(window.observed) < 5*time.Millisecond {
				heavy = append(heavy, pid)
				return nil
			}
			if !window.tailProbed && result.AppID == "" && !expired() {
				if tail, err := descriptorTail(&f, pid, expired); err == nil {
					o.mu.Lock()
					current := o.windows[pid]
					if current.directory == metadata.Ino {
						current.tailProbed = true
						current.extent = max(current.extent, tail)
						o.windows[pid] = current
					}
					o.mu.Unlock()
					if _, err := f.Seek(max(0, tail-255)+2, 0); err == nil {
						_, _ = visitFDs(256)
						if matched {
							return nil
						}
					}
				}
			}
		}
		if _, err := f.Seek(position, 0); err != nil {
			return nil
		}
		for !expired() {
			names, readErr := visitFDs(64)
			whole = position == 0 && errors.Is(readErr, io.EOF) && !expired()
			if matched {
				return nil
			}
			if readErr != nil || names < 64 {
				if !complete && position > 0 {
					heavy = append(heavy, pid)
				}
				o.mu.Lock()
				if current := o.windows[pid]; current.directory == metadata.Ino {
					current.next = 0
					o.windows[pid] = current
				}
				o.mu.Unlock()
				break
			}
			// A large unrelated process must not consume the rest of this
			// lookup's budget. Resume its next window after visiting its peers.
			heavy = append(heavy, pid)
			break
		}
		return nil
	}
	finish := func() (platform.Owner, error) {
		// Another scanner may have published a conflicting live holder while
		// this lookup validated its first one. Recheck all available hints.
		if !expired() {
			if err := o.indexed(r.inode).visit(accept); err != nil {
				return platform.Owner{}, err
			}
		}
		// Finding one holder does not authorize skipping the remaining
		// conflict checks. Metadata validation itself can cross the deadline,
		// so guard the final result after visiting all available hints too.
		if expired() {
			return platform.Owner{}, fmt.Errorf("%w (uid=%d inode=%d hints=%d pids=%d fds=%d lastPID=%d fdUID=%d indexed=%t frontier=%d indexWait=%s validation=%s scope=%s)", context.DeadlineExceeded, r.uid, r.inode, hinted, scannedPIDs, scannedFDs, lastPID, lastUID, lastIndexed, lastPosition, initialIndexTime, validationTime, scopeTime)
		}
		if result.AppID == "" {
			return result, os.ErrNotExist
		}
		result.Generation = r.generation()
		if r.protocol == unix.IPPROTO_UDP {
			o.cacheHolders(r.cookie, found)
		}
		o.rememberPID(r.uid, result.PID)
		return result, nil
	}
	// Search each tier for actual holders, then fall back only if it found
	// none. A matching scope never supplies identity by itself.
	scopeStarted := time.Now()
	groups := o.cgroupPIDsTimed(ctx, r.cgroup, requested, &timing)
	scopeTime = time.Since(scopeStarted)
	if expired() {
		return finish()
	}
	ordered := make([]uint32, 0, len(groups))
	for _, pid := range recent {
		if slices.Contains(groups, pid) {
			ordered = append(ordered, pid)
		}
	}
	for _, pid := range groups {
		if !slices.Contains(ordered, pid) {
			ordered = append(ordered, pid)
		}
	}
	if result.AppID == "" {
		started := time.Now()
		o.prioritizeScope(ctx, ordered, recent, r.uid)
		timing.add(phaseRank, time.Since(started))
	}
	for _, pid := range ordered {
		if err := scan(pid, false); err != nil {
			return platform.Owner{}, err
		}
	}
	if result.AppID != "" {
		return finish()
	}
	// Finish the hinted cgroup before spending the remaining budget on
	// unrelated UIDs and processes. Recheck neighbours' newly indexed rows.
	if err := o.indexed(r.inode).visit(accept); err != nil {
		return platform.Owner{}, err
	}
	if result.AppID != "" {
		return finish()
	}
	groupHeavy := append([]uint32(nil), heavy...)
	for _, pid := range groupHeavy {
		delete(seen, pid)
		if err := scan(pid, true); err != nil {
			return platform.Owner{}, err
		}
		if result.AppID != "" {
			return finish()
		}
	}
	// Recent real holders are stronger hints than directory order, including
	// hosts without delegated cgroups. Exhaust their targeted pass first.
	for _, pid := range recent {
		delete(seen, pid)
		if err := scan(pid, true); err != nil {
			return platform.Owner{}, err
		}
		if result.AppID != "" {
			return finish()
		}
	}
	// An expired lookup must not do a full /proc enumeration on its way
	// out. Under a burst, those discarded walks took CPU from the lookups
	// whose deadlines had not expired yet and amplified the initial misses.
	if expired() {
		return finish()
	}

	entries, _ := os.ReadDir("/proc")
	var sameUID, other []uint32
	for i := len(entries) - 1; i >= 0 && !expired(); i-- {
		if notice != nil && result.AppID == "" {
			select {
			case <-notice.ready:
				if err := checkHints(); err != nil {
					return platform.Owner{}, err
				}
				if result.AppID != "" {
					return finish()
				}
			default:
			}
		}
		e := entries[i]
		pid, err := strconv.ParseUint(e.Name(), 10, 32)
		if err != nil || seen[uint32(pid)] {
			continue
		}
		var st unix.Stat_t
		if unix.Stat("/proc/"+e.Name(), &st) != nil {
			continue
		}
		if st.Uid == r.uid {
			sameUID = append(sameUID, uint32(pid))
		} else {
			other = append(other, uint32(pid))
		}
	}
	slices.Sort(sameUID)
	slices.Reverse(sameUID)
	ordered = ordered[:0]
	for _, pid := range recent {
		if slices.Contains(sameUID, pid) {
			ordered = append(ordered, pid)
		}
	}
	for _, pid := range sameUID {
		if !slices.Contains(ordered, pid) {
			ordered = append(ordered, pid)
		}
	}
	for _, pid := range ordered {
		if err := scan(pid, false); err != nil {
			return platform.Owner{}, err
		}
	}
	if result.AppID != "" {
		return finish()
	}
	slices.Sort(other)
	slices.Reverse(other)
	for _, pid := range other {
		if err := scan(pid, false); err != nil {
			return platform.Owner{}, err
		}
	}
	if result.AppID != "" {
		return finish()
	}
	// Other concurrent lookups may have found this new socket while scanning
	// a neighbouring window. Check those hints before the remaining full scan.
	if err := o.indexed(r.inode).visit(accept); err != nil {
		return platform.Owner{}, err
	}
	if result.AppID != "" {
		return finish()
	}
	for len(heavy) > 0 && !expired() {
		pending := heavy
		heavy = nil
		visited := map[uint32]bool{}
		for _, pid := range pending {
			if visited[pid] {
				continue
			}
			visited[pid] = true
			delete(seen, pid)
			if err := scan(pid, true); err != nil {
				return platform.Owner{}, err
			}
			if result.AppID != "" {
				return finish()
			}
		}
	}
	return finish()
}

// FDSize bounds the allocated descriptor table. proc's fd+2 directory offsets
// let us locate its occupied tail without reading thousands of regular-file
// symlinks. This is a search hint only; socket inode and process identity are
// still checked by holders. The tiny getdents buffer asks for one entry.
func descriptorTail(f *procDescriptors, pid uint32, expired func() bool) (int64, error) {
	b, err := readKernelFile(fmt.Sprintf("/proc/%d/status", pid), 64<<10)
	if err != nil {
		return 0, err
	}
	var size int64
	for _, line := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(line, "FDSize:") {
			size, err = strconv.ParseInt(strings.TrimSpace(strings.TrimPrefix(line, "FDSize:")), 10, 64)
			break
		}
	}
	if err != nil || size <= 0 {
		return 0, os.ErrNotExist
	}
	lo, hi, last := int64(0), size-1, int64(0)
	var data [32]byte
	for lo <= hi {
		if expired() {
			return 0, context.DeadlineExceeded
		}
		mid := lo + (hi-lo)/2
		if _, err := f.Seek(mid+2, 0); err != nil {
			return 0, err
		}
		n, err := unix.ReadDirent(f.fd, data[:])
		if err != nil {
			return 0, err
		}
		if n == 0 {
			hi = mid - 1
			continue
		}
		_, _, names := unix.ParseDirent(data[:n], 1, nil)
		if len(names) == 0 {
			return 0, os.ErrNotExist
		}
		fd, err := strconv.ParseInt(names[0], 10, 64)
		if err != nil {
			return 0, err
		}
		last = max(last, fd)
		lo = fd + 1
	}
	return last, nil
}

func (o *Owners) Snapshot(ctx context.Context, keys []netip.AddrPort) (map[netip.AddrPort]platform.Owner, error) {
	return o.SnapshotAt(ctx, keys, time.Now())
}

func (o *Owners) SnapshotAt(ctx context.Context, keys []netip.AddrPort, started time.Time) (map[netip.AddrPort]platform.Owner, error) {
	rows := map[int][]socketRow{}
	for _, fam := range []int{unix.AF_INET, unix.AF_INET6} {
		need := false
		for _, k := range keys {
			if familyOf(k.Addr()) == fam || fam == unix.AF_INET6 {
				need = true
				break
			}
		}
		if !need {
			continue
		}
		v, err := diagDump(ctx, fam, unix.IPPROTO_UDP, netip.AddrPort{})
		if err != nil {
			return nil, err
		}
		rows[fam] = v
	}
	// Index the dump by port once. Reconciliation is linear in socket count.
	byPort := map[uint16][]socketRow{}
	for _, familyRows := range rows {
		for _, r := range familyRows {
			byPort[r.local.Port()] = append(byPort[r.local.Port()], r)
		}
	}
	// Keep only cookies referenced by engine sessions (including pending
	// ones). A capped app can keep its refused kernel sockets open forever;
	// their existence alone must not retain an unbounded ownership cache.
	live := make(map[uint64]bool, len(keys))
	out := make(map[netip.AddrPort]platform.Owner, len(keys))
	processes := map[uint32]platform.Owner{}
	checked := map[uint32]bool{}
	for _, k := range keys {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		r, err := matchUDP(byPort[k.Port()], k)
		if errors.Is(err, errSocketAmbiguous) {
			for _, candidate := range udpCandidates(byPort[k.Port()], k) {
				live[candidate.cookie] = true
			}
			o.mu.Lock()
			o.ambiguousPorts[k.Port()] = time.Now().Add(2 * time.Second)
			o.mu.Unlock()
			out[k] = platform.Owner{Generation: cookieSet(byPort[k.Port()], k)}
			continue
		}
		if err != nil {
			continue
		}
		live[r.cookie] = true
		cached := o.cachedHolders(r.cookie)
		var owner platform.Owner
		if len(cached) == 0 {
			out[k] = platform.Owner{Generation: r.generation()}
			continue
		}
		// Reconcile every cookie, plus revalidate recorded holders. A changed
		// holder is resolved afresh on the next datagram after closing the mapping.
		for _, h := range cached {
			if !checked[h.pid] {
				processes[h.pid], _ = processOwner(h.pid)
				checked[h.pid] = true
			}
			v := processes[h.pid]
			if v.StartTime != h.start || v.AppID == "" {
				continue
			}
			inode, ok := socketInodeAt(unix.AT_FDCWD, fmt.Sprintf("/proc/%d/fd/%s", h.pid, h.fd))
			if !ok || inode != r.inode {
				continue
			}
			if owner.AppID != "" && owner.AppID != v.AppID {
				owner = platform.Owner{}
				break
			}
			if owner.AppID == "" {
				owner = v
			}
		}
		if owner.AppID != "" {
			owner.Generation = r.generation()
			out[k] = owner
		}
	}
	o.mu.Lock()
	for port, until := range o.ambiguousPorts {
		if !time.Now().Before(until) {
			delete(o.ambiguousPorts, port)
		}
	}
	o.mu.Unlock()
	o.pruneCookies(live, started)
	return out, nil
}
