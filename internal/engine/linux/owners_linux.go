//go:build linux

package linux

import (
	"bytes"
	"context"
	"errors"
	"fmt"
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
	next       int64
	high       int64 // end of the sequentially indexed range; tail probes cannot advance it
	extent     int64 // largest descriptor observed, including tail probes
	lastFD     int64
	tailProbed bool
	observed   time.Time
	scanning   chan struct{}
}
type Owners struct {
	queries         diagPool
	warmed          bool
	lookupErrors    [4]atomic.Uint64
	cgroupStats     [3]atomic.Uint64
	lastLookupError atomic.Pointer[string]
	mu              sync.Mutex
	cgroups         map[uint64]string
	recent          map[uint32][]uint32
	cache           map[uint64]cachedHolders
	inodes          map[uint32]inodeHolders
	waiters         map[uint32]*inodeWaiter
	windows         map[uint32]fdWindow
	ambiguousPorts  map[uint16]time.Time
	// Fault callbacks are assigned only by the acceptance build.
	fault        func(context.Context) error
	destroyFault func(context.Context, socketRow, func())
}

type lookupStats struct {
	Timeout, Missing, Ambiguous, Other           uint64
	CgroupHints, CgroupResolved, CgroupPopulated uint64
	LastError                                    string
	MetadataRejected                             uint64
	LastMetadataError                            string
}

func (o *Owners) Stats() any {
	s := lookupStats{Timeout: o.lookupErrors[0].Load(), Missing: o.lookupErrors[1].Load(), Ambiguous: o.lookupErrors[2].Load(), Other: o.lookupErrors[3].Load()}
	s.CgroupHints, s.CgroupResolved, s.CgroupPopulated = o.cgroupStats[0].Load(), o.cgroupStats[1].Load(), o.cgroupStats[2].Load()
	s.MetadataRejected = rejectedMetadata.Load()
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
	// Allocate the bounded index's backing tables before capture. Growing
	// them under the shared lock can turn one GC assist into many timeouts.
	return &Owners{cgroups: make(map[uint64]string, 256), recent: make(map[uint32][]uint32, 64), cache: make(map[uint64]cachedHolders, 65536), inodes: make(map[uint32]inodeHolders, 131072), waiters: make(map[uint32]*inodeWaiter, 32768), windows: make(map[uint32]fdWindow, 4096), ambiguousPorts: map[uint16]time.Time{}}
}

func (o *Owners) Close() { o.queries.close() }
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
	for _, r := range rows {
		if r.local == t.Source && r.remote == t.Destination {
			owner, err = o.holders(ctx, r)
			if err != nil {
				err = fmt.Errorf("TCP holder scan: %w", err)
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
	storage := processBuffers.Get().(*[16 << 10]byte)
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

// The caller has already read this incarnation's start time. Verify it again
// after reading executable metadata, without a redundant third stat read.
func processOwnerAt(pid uint32, start uint64) (platform.Owner, error) {
	root := fmt.Sprintf("/proc/%d/", pid)
	exe, err := readProcLink(root + "exe")
	if err != nil {
		return platform.Owner{}, err
	}
	exe = strings.TrimSuffix(exe, " (deleted)")
	id := apppath.Normalize(exe, apppath.Linux)
	storage := processBuffers.Get().(*[16 << 10]byte)
	// Flatpak's mount namespace metadata identifies apps that have identical
	// /app/bin executable paths. It belongs to the holder, never to the socket.
	flatpak := flatpakBuffers.Get().(*[64 << 10]byte)
	info, infoErr := readFlatpakInfo(root+"root", flatpak[:])
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
	flatpakBuffers.Put(flatpak)
	processBuffers.Put(storage)
	end, err := processStart(pid)
	if err != nil || end != start {
		return platform.Owner{}, os.ErrNotExist
	}
	return platform.Owner{PID: pid, StartTime: start, Path: exe, AppID: id}, nil
}

func (o *Owners) cgroupPIDs(ctx context.Context, id uint64) []uint32 {
	if id == 0 {
		return nil
	}
	o.cgroupStats[0].Add(1)
	o.mu.Lock()
	dir := o.cgroups[id]
	o.mu.Unlock()
	if dir == "" {
		_ = o.refreshCgroups(ctx)
		o.mu.Lock()
		dir = o.cgroups[id]
		o.mu.Unlock()
	}
	if dir == "" {
		return nil
	}
	o.cgroupStats[1].Add(1)
	storage := processBuffers.Get().(*[16 << 10]byte)
	defer processBuffers.Put(storage)
	path := filepath.Join(dir, "cgroup.procs")
	b, err := readInto(path, storage[:])
	if errors.Is(err, errKernelFileLimit) {
		b, err = readKernelFile(path, 1<<20)
	}
	if err != nil {
		return nil
	}
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
	o.mu.Lock()
	if len(o.cgroups) > 8192 {
		clear(o.cgroups)
	}
	for id, path := range found {
		o.cgroups[id] = path
	}
	o.mu.Unlock()
	return err
}

func (o *Owners) holders(ctx context.Context, r socketRow) (platform.Owner, error) {
	if r.inode == 0 {
		return platform.Owner{}, os.ErrNotExist
	}
	target := "socket:[" + strconv.FormatUint(uint64(r.inode), 10) + "]"
	deadline, timed := ctx.Deadline()
	expired := func() bool { return ctx.Err() != nil || (timed && !time.Now().Before(deadline)) }
	var result platform.Owner
	var found []holder
	var scanWait time.Duration
	var scannedPIDs, scannedFDs, hinted int
	var lastPID, lastUID, waitPID uint32
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
		start, err := processStart(h.pid)
		if err != nil || start != h.start {
			return nil
		}
		got, err := readProcLink(fmt.Sprintf("/proc/%d/fd/%s", h.pid, h.fd))
		if err != nil || got != target {
			return nil
		}
		live, err := processOwnerAt(h.pid, start)
		if err != nil || live.StartTime != h.start {
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
				window = fdWindow{start: h.start, lastFD: -1, scanning: window.scanning}
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
	o.mu.Lock()
	cached := o.cache[r.cookie].holders
	indexed := o.inodes[r.inode]
	hinted += len(cached) + indexed.count()
	recent := o.recent[r.uid]
	o.mu.Unlock()
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
	scan := func(pid uint32, complete bool) error {
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
		start, err := processStart(pid)
		if err != nil {
			return nil
		}
		dir := fmt.Sprintf("/proc/%d/fd", pid)
		// One scanner per process. Followers consume the inode hints it
		// publishes instead of issuing the same hundreds of readlinks again.
		gate := make(chan struct{})
		remember := make(map[uint32]holder, 32)
		if expired() {
			return nil
		}
		if err := checkHints(); err != nil {
			return err
		}
		if hasHolder(pid) {
			return nil
		}
		o.mu.Lock()
		if len(o.windows) > 4096 {
			for old, state := range o.windows {
				if old != pid && state.scanning == nil {
					delete(o.windows, old)
				}
				if len(o.windows) <= 4096 {
					break
				}
			}
		}
		current := o.windows[pid]
		for current.scanning != nil {
			// Do not mark a busy candidate as searched and walk unrelated
			// processes. Wait for its bounded scan (or our own deadline),
			// consume published matches, then scan this same PID's next window.
			// A channel wake, rather than a sub-millisecond timer, avoids both
			// scheduler rounding and losing the useful candidate under load.
			busy := current.scanning
			waitPID = pid
			o.mu.Unlock()
			waiting := time.Now()
			var ready <-chan struct{}
			if notice != nil && result.AppID == "" {
				ready = notice.ready
			}
			select {
			case <-busy:
			case <-ready:
			case <-ctx.Done():
			}
			scanWait += time.Since(waiting)
			if err := checkHints(); err != nil {
				return err
			}
			if hasHolder(pid) || expired() {
				return nil
			}
			o.mu.Lock()
			current = o.windows[pid]
		}
		current.scanning = gate
		o.windows[pid] = current
		o.mu.Unlock()
		defer func() {
			o.mu.Lock()
			window := o.windows[pid]
			window.scanning = nil
			o.windows[pid] = window
			close(gate)
			o.mu.Unlock()
		}()
		f, err := os.Open(dir)
		if err != nil {
			return nil
		}
		defer f.Close()
		var metadata unix.Stat_t
		canIndex := (unix.Fstat(int(f.Fd()), &metadata) == nil && metadata.Uid == r.uid) || slices.Contains(recent, pid)
		lastPID, lastUID, lastIndexed = pid, metadata.Uid, canIndex
		o.mu.Lock()
		window := o.windows[pid]
		if window.start != start {
			window = fdWindow{start: start, lastFD: -1, scanning: gate}
		}
		// Once a live holder is known, reuse other processes' very recent
		// search windows. A burst must not rescan the same 64 descriptors in
		// every concurrent lookup. Positive hints are always revalidated above.
		if !complete && result.AppID != "" && time.Since(window.observed) < 5*time.Millisecond {
			o.mu.Unlock()
			return nil
		}
		position := window.next
		lastPosition = window.high
		window.next += 64
		o.windows[pid] = window
		o.mu.Unlock()
		if position > 0 {
			if _, err := f.Seek(position, 0); err != nil {
				return nil
			}
		}
		maxFD := window.high
		maxSeen := window.extent
		advancing := false
		visit := func(names []string) error {
			for _, fd := range names {
				if expired() {
					break
				}
				scannedFDs++
				if scannedFDs%32 == 0 && result.AppID == "" {
					if err := checkHints(); err != nil {
						return err
					}
				}
				if number, err := strconv.ParseInt(fd, 10, 64); err == nil {
					maxSeen = max(maxSeen, number)
					if advancing {
						maxFD = max(maxFD, number)
					}
				}
				got, err := readProcLink(dir + "/" + fd)
				if err != nil || !strings.HasPrefix(got, "socket:[") || !strings.HasSuffix(got, "]") {
					continue
				}
				inode, err := strconv.ParseUint(got[8:len(got)-1], 10, 32)
				if err != nil {
					continue
				}
				h := holder{pid, start, fd}
				if canIndex || uint32(inode) == r.inode {
					remember[uint32(inode)] = h
					if len(remember) >= 32 {
						o.publish(remember)
						clear(remember)
					}
				}
				if uint32(inode) == r.inode {
					if err := accept(h); err != nil {
						return err
					}
				}
			}
			return nil
		}
		defer func() {
			o.publish(remember)
			o.mu.Lock()
			defer o.mu.Unlock()
			if current := o.windows[pid]; current.start == start {
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
				names, _ := f.Readdirnames(1024)
				if err := visit(names); err != nil {
					return err
				}
			}
			return nil
		}
		if complete && canIndex && window.extent >= 128 {
			if err := recentRange(); err != nil {
				return err
			}
			if hasHolder(pid) {
				return nil
			}
		}
		if !complete {
			// Small descriptor sets are commonly reused by concurrent short
			// connections. The last descriptor alone misses its neighbours.
			if window.lastFD >= 0 && window.lastFD < 128 {
				if _, err := f.Seek(0, 0); err == nil {
					names, _ := f.Readdirnames(128)
					if err := visit(names); err != nil {
						return err
					}
					if len(found) > 0 && found[len(found)-1].pid == pid {
						return nil
					}
				}
			}
			// Reopening normally reuses the previous descriptor. Check that
			// one live link even when another lookup just scanned this process.
			if window.lastFD >= 0 {
				if err := visit([]string{strconv.FormatInt(window.lastFD, 10)}); err != nil {
					return err
				}
				if len(found) > 0 && found[len(found)-1].pid == pid {
					return nil
				}
			}
			// Scan newly allocated descriptors first. Everything below this
			// high-water mark was already indexed by a prior window; rescanning
			// 256 neighbours in every unrelated process made multi-app bursts
			// spend their entire lookup budget reading the same symlinks.
			if _, err := f.Seek(window.high+3, 0); err == nil {
				count := 128
				if canIndex {
					count = 512
				}
				names, _ := f.Readdirnames(count)
				advancing = true
				if err := visit(names); err != nil {
					return err
				}
				advancing = false
				if len(found) > 0 && found[len(found)-1].pid == pid {
					return nil
				}
			}
			if canIndex && window.extent >= 128 && len(recent) > 0 && recent[0] == pid {
				if err := recentRange(); err != nil {
					return err
				}
				if hasHolder(pid) {
					return nil
				}
			}
			if time.Since(window.observed) < 5*time.Millisecond {
				heavy = append(heavy, pid)
				return nil
			}
			if !window.tailProbed && result.AppID == "" && !expired() {
				if tail, err := descriptorTail(f, pid, expired); err == nil {
					o.mu.Lock()
					current := o.windows[pid]
					if current.start == start {
						current.tailProbed = true
						current.extent = max(current.extent, tail)
						o.windows[pid] = current
					}
					o.mu.Unlock()
					if _, err := f.Seek(max(0, tail-255)+2, 0); err == nil {
						names, _ := f.Readdirnames(256)
						if err := visit(names); err != nil {
							return err
						}
						if len(found) > 0 && found[len(found)-1].pid == pid {
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
			names, readErr := f.Readdirnames(64)
			if err := visit(names); err != nil {
				return err
			}
			if len(found) > 0 && found[len(found)-1].pid == pid {
				return nil
			}
			if readErr != nil {
				if !complete && position > 0 {
					heavy = append(heavy, pid)
				}
				o.mu.Lock()
				if current := o.windows[pid]; current.start == start {
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
		if result.AppID == "" {
			if expired() {
				return result, fmt.Errorf("%w (uid=%d inode=%d hints=%d pids=%d fds=%d scanWait=%s waitPID=%d lastPID=%d fdUID=%d indexed=%t frontier=%d)", context.DeadlineExceeded, r.uid, r.inode, hinted, scannedPIDs, scannedFDs, scanWait, waitPID, lastPID, lastUID, lastIndexed, lastPosition)
			}
			return result, os.ErrNotExist
		}
		result.Generation = r.generation()
		newRecent := make([]uint32, 1, 32)
		newRecent[0] = result.PID
		o.mu.Lock()
		if r.protocol == unix.IPPROTO_UDP {
			o.cache[r.cookie] = cachedHolders{found, time.Now()}
		}
		for _, pid := range o.recent[r.uid] {
			if pid != result.PID && len(newRecent) < 32 {
				newRecent = append(newRecent, pid)
			}
		}
		o.recent[r.uid] = newRecent
		o.mu.Unlock()
		return result, nil
	}
	// Search each tier for actual holders, then fall back only if it found
	// none. A matching scope never supplies identity by itself.
	groups := o.cgroupPIDs(ctx, r.cgroup)
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
func descriptorTail(f *os.File, pid uint32, expired func() bool) (int64, error) {
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
		n, err := unix.ReadDirent(int(f.Fd()), data[:])
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
		o.mu.Lock()
		cached := o.cache[r.cookie].holders
		o.mu.Unlock()
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
			link, err := readProcLink(fmt.Sprintf("/proc/%d/fd/%s", h.pid, h.fd))
			if err != nil || link != "socket:["+strconv.FormatUint(uint64(r.inode), 10)+"]" {
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
	for cookie, cached := range o.cache {
		if !live[cookie] && cached.observed.Before(started) {
			delete(o.cache, cookie)
		}
	}
	o.mu.Unlock()
	return out, nil
}
