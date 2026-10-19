//go:build linux

package linux

import (
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
	high       int64
	lastFD     int64
	tailProbed bool
	observed   time.Time
	scanning   chan struct{}
}
type Owners struct {
	warmed          bool
	lookupErrors    [4]atomic.Uint64
	cgroupStats     [3]atomic.Uint64
	lastLookupError atomic.Pointer[string]
	mu              sync.Mutex
	cgroups         map[uint64]string
	recent          map[uint32][]uint32
	cache           map[uint64]cachedHolders
	inodes          map[uint32][]holder
	windows         map[uint32]fdWindow
	ambiguousPorts  map[uint16]bool
	// Fault callbacks are assigned only by the acceptance build.
	fault        func(context.Context) error
	destroyFault func(context.Context, socketRow, func())
}

type lookupStats struct {
	Timeout, Missing, Ambiguous, Other           uint64
	CgroupHints, CgroupResolved, CgroupPopulated uint64
	LastError                                    string
}

func (o *Owners) Stats() any {
	s := lookupStats{Timeout: o.lookupErrors[0].Load(), Missing: o.lookupErrors[1].Load(), Ambiguous: o.lookupErrors[2].Load(), Other: o.lookupErrors[3].Load()}
	s.CgroupHints, s.CgroupResolved, s.CgroupPopulated = o.cgroupStats[0].Load(), o.cgroupStats[1].Load(), o.cgroupStats[2].Load()
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
			if _, err := diag(ctx, family, protocol, endpoint, endpoint, false); err != nil && !errors.Is(err, unix.ENOENT) {
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
	return &Owners{cgroups: map[uint64]string{}, recent: map[uint32][]uint32{}, cache: map[uint64]cachedHolders{}, inodes: map[uint32][]holder{}, windows: map[uint32]fdWindow{}, ambiguousPorts: map[uint16]bool{}}
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
	rows, err := diag(ctx, familyOf(t.Source.Addr()), unix.IPPROTO_TCP, t.Source, t.Destination, false)
	if errors.Is(err, unix.ENOENT) && t.Source.Addr().Is4() {
		rows, err = diag(ctx, unix.AF_INET6, unix.IPPROTO_TCP, t.Source, t.Destination, false)
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
	exact, err := diag(ctx, familyOf(source.Addr()), unix.IPPROTO_UDP, source, tuple.Destination, false)
	if err != nil && !errors.Is(err, unix.ENOENT) {
		return platform.Owner{}, fmt.Errorf("UDP exact query: %w", err)
	}
	o.mu.Lock()
	ambiguous := o.ambiguousPorts[source.Port()]
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
		o.ambiguousPorts[source.Port()] = true
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
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return 0, err
	}
	end := strings.LastIndexByte(string(b), ')')
	if end < 0 {
		return 0, errors.New("bad process stat")
	}
	f := strings.Fields(string(b[end+1:]))
	if len(f) < 20 {
		return 0, errors.New("short process stat")
	}
	return strconv.ParseUint(f[19], 10, 64)
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
	exe, err := os.Readlink(root + "exe")
	if err != nil {
		return platform.Owner{}, err
	}
	exe = strings.TrimSuffix(exe, " (deleted)")
	id := apppath.Normalize(exe, apppath.Linux)
	// Flatpak's mount namespace metadata identifies apps that have identical
	// /app/bin executable paths. It belongs to the holder, never to the socket.
	if b, err := os.ReadFile(root + "root/.flatpak-info"); err == nil {
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
	} else if b, err := os.ReadFile(root + "environ"); err == nil {
		for _, v := range strings.Split(string(b), "\x00") {
			if strings.HasPrefix(v, "APPIMAGE=") {
				name := filepath.Base(strings.TrimPrefix(v, "APPIMAGE="))
				if strings.HasSuffix(strings.ToLower(name), ".appimage") {
					id = "appimage:" + name[:len(name)-9]
				}
				break
			}
		}
	}
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
	b, err := os.ReadFile(filepath.Join(dir, "cgroup.procs"))
	if err != nil {
		return nil
	}
	var pids []uint32
	for _, s := range strings.Fields(string(b)) {
		v, e := strconv.ParseUint(s, 10, 32)
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
		got, err := os.Readlink(fmt.Sprintf("/proc/%d/fd/%s", h.pid, h.fd))
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
				window = fdWindow{start: h.start, scanning: window.scanning}
			}
			window.lastFD = fd
			window.observed = time.Now()
			o.windows[h.pid] = window
			o.mu.Unlock()
		}
		return nil
	}
	o.mu.Lock()
	cached := append([]holder(nil), o.cache[r.cookie].holders...)
	cached = append(cached, o.inodes[r.inode]...)
	recent := append([]uint32(nil), o.recent[r.uid]...)
	o.mu.Unlock()
	for _, h := range cached {
		if err := accept(h); err != nil {
			return platform.Owner{}, err
		}
	}

	// /proc's fd directory is seekable: its position is fd+2 (fs/proc/fd.c).
	// Concurrent cold lookups share small rotating windows and index sockets
	// seen along the way. The index is only a hint; accept rechecks the live fd
	// and PID start time on every use. Regular files never enter the index.
	var heavy []uint32
	scan := func(pid uint32, complete bool) error {
		if seen[pid] || expired() {
			return nil
		}
		seen[pid] = true
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
		var gate chan struct{}
		for {
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
			window := o.windows[pid]
			if window.scanning == nil {
				gate = make(chan struct{})
				window.scanning = gate
				o.windows[pid] = window
				o.mu.Unlock()
				break
			}
			wait := window.scanning
			o.mu.Unlock()
			select {
			case <-ctx.Done():
				return nil
			case <-wait:
			}
			o.mu.Lock()
			hints := append([]holder(nil), o.inodes[r.inode]...)
			o.mu.Unlock()
			for _, h := range hints {
				if err := accept(h); err != nil {
					return err
				}
			}
			if result.AppID != "" {
				return nil
			}
		}
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
		o.mu.Lock()
		window := o.windows[pid]
		if window.start != start {
			window = fdWindow{start: start, scanning: gate}
		}
		// Once a live holder is known, reuse other processes' very recent
		// search windows. A burst must not rescan the same 64 descriptors in
		// every concurrent lookup. Positive hints are always revalidated above.
		if !complete && result.AppID != "" && time.Since(window.observed) < 5*time.Millisecond {
			o.mu.Unlock()
			return nil
		}
		position := window.next
		window.next += 64
		o.windows[pid] = window
		o.mu.Unlock()
		if position > 0 {
			if _, err := f.Seek(position, 0); err != nil {
				return nil
			}
		}
		remember := map[uint32]holder{}
		maxFD := window.high
		visit := func(names []string) error {
			for _, fd := range names {
				if expired() {
					break
				}
				if number, err := strconv.ParseInt(fd, 10, 64); err == nil {
					maxFD = max(maxFD, number)
				}
				got, err := os.Readlink(dir + "/" + fd)
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
			o.mu.Lock()
			defer o.mu.Unlock()
			if current := o.windows[pid]; current.start == start {
				current.high = max(current.high, maxFD)
				current.observed = time.Now()
				o.windows[pid] = current
			}
			if len(o.inodes) > 131072 {
				clear(o.inodes)
			}
			for inode, h := range remember {
				old := o.inodes[inode]
				if !slices.Contains(old, h) && len(old) < 8 {
					o.inodes[inode] = append(old, h)
				}
			}
		}()
		if !complete {
			// Reopening normally reuses the previous descriptor. Check that
			// one live link even when another lookup just scanned this process.
			if window.lastFD > 0 {
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
				names, _ := f.Readdirnames(128)
				if err := visit(names); err != nil {
					return err
				}
				if len(found) > 0 && found[len(found)-1].pid == pid {
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
						current.high = max(current.high, tail)
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
				return result, context.DeadlineExceeded
			}
			return result, os.ErrNotExist
		}
		result.Generation = r.generation()
		o.mu.Lock()
		if r.protocol == unix.IPPROTO_UDP {
			o.cache[r.cookie] = cachedHolders{found, time.Now()}
		}
		newRecent := []uint32{result.PID}
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
	o.mu.Lock()
	groupHints := append([]holder(nil), o.inodes[r.inode]...)
	o.mu.Unlock()
	for _, h := range groupHints {
		if err := accept(h); err != nil {
			return platform.Owner{}, err
		}
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

	entries, _ := os.ReadDir("/proc")
	var sameUID, other []uint32
	for i := len(entries) - 1; i >= 0 && !expired(); i-- {
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
	o.mu.Lock()
	hints := append([]holder(nil), o.inodes[r.inode]...)
	o.mu.Unlock()
	for _, h := range hints {
		if err := accept(h); err != nil {
			return platform.Owner{}, err
		}
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
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
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
	started := time.Now()
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
	// Discard only dead cookies from a complete dump, and never a cache entry
	// created while that dump was in progress. TCP lookups aren't retained.
	live := map[uint64]bool{}
	for _, familyRows := range rows {
		for _, row := range familyRows {
			live[row.cookie] = true
		}
	}
	o.mu.Lock()
	for cookie, cached := range o.cache {
		if !live[cookie] && cached.observed.Before(started) {
			delete(o.cache, cookie)
		}
	}
	o.mu.Unlock()
	out := make(map[netip.AddrPort]platform.Owner, len(keys))
	processes := map[uint32]platform.Owner{}
	checked := map[uint32]bool{}
	for _, k := range keys {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		r, err := matchUDP(byPort[k.Port()], k)
		if errors.Is(err, errSocketAmbiguous) {
			o.mu.Lock()
			o.ambiguousPorts[k.Port()] = true
			o.mu.Unlock()
			out[k] = platform.Owner{Generation: cookieSet(byPort[k.Port()], k)}
			continue
		}
		if err != nil {
			continue
		}
		o.mu.Lock()
		cached := append([]holder(nil), o.cache[r.cookie].holders...)
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
			link, err := os.Readlink(fmt.Sprintf("/proc/%d/fd/%s", h.pid, h.fd))
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
	return out, nil
}
