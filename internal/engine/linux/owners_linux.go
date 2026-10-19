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
	"time"

	"github.com/AyoubAchour/net-switch/internal/engine/platform"
	"golang.org/x/sys/unix"
)

type holder struct {
	pid   uint32
	start uint64
	fd    string
}
type Owners struct {
	mu      sync.Mutex
	cgroups map[uint64]string
	recent  map[uint32][]uint32
	cache   map[uint64][]holder
	// Fault callbacks are assigned only by the acceptance build.
	fault        func(context.Context) error
	destroyFault func(context.Context, socketRow, func())
}

func NewOwners() *Owners {
	return &Owners{cgroups: map[uint64]string{}, recent: map[uint32][]uint32{}, cache: map[uint64][]holder{}}
}

// Work stops short of 10 ms to leave room for returning, timing and policy
// admission. The caller's earlier cancellation always wins.
func lookupContext(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(ctx, 8*time.Millisecond)
}
func (o *Owners) TCP(ctx context.Context, t platform.Tuple) (platform.Owner, error) {
	if o.fault != nil {
		if err := o.fault(ctx); err != nil {
			return platform.Owner{}, err
		}
	}
	ctx, cancel := lookupContext(ctx)
	defer cancel()
	rows, err := diag(ctx, familyOf(t.Source.Addr()), unix.IPPROTO_TCP, t.Source, t.Destination, false)
	if errors.Is(err, unix.ENOENT) {
		rows, err = diagDump(ctx, familyOf(t.Source.Addr()), unix.IPPROTO_TCP, t.Source)
	}
	if err != nil {
		return platform.Owner{}, err
	}
	for _, r := range rows {
		if r.local == t.Source && r.remote == t.Destination {
			return o.holders(ctx, r)
		}
	}
	return platform.Owner{}, os.ErrNotExist
}
func (o *Owners) UDP(ctx context.Context, source netip.AddrPort) (platform.Owner, error) {
	if o.fault != nil {
		if err := o.fault(ctx); err != nil {
			return platform.Owner{}, err
		}
	}
	ctx, cancel := lookupContext(ctx)
	defer cancel()
	// Exact lookup is useful for the common wildcard socket. A port-filtered
	// dump also detects SO_REUSEPORT ambiguity instead of accepting the arbitrary
	// socket that the kernel's inbound hash selected.
	_, err := diag(ctx, familyOf(source.Addr()), unix.IPPROTO_UDP, source, netip.AddrPort{}, false)
	if err != nil && !errors.Is(err, unix.ENOENT) {
		return platform.Owner{}, err
	}
	rows, err := diagDump(ctx, familyOf(source.Addr()), unix.IPPROTO_UDP, source)
	if err != nil {
		return platform.Owner{}, err
	}
	r, err := matchUDP(rows, source)
	if errors.Is(err, errSocketAmbiguous) {
		return platform.Owner{}, platform.ErrAmbiguous
	}
	if err != nil {
		return platform.Owner{}, err
	}
	return o.holders(ctx, r)
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
	root := fmt.Sprintf("/proc/%d/", pid)
	exe, err := os.Readlink(root + "exe")
	if err != nil {
		return platform.Owner{}, err
	}
	exe = strings.TrimSuffix(exe, " (deleted)")
	id := exe
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
	o.mu.Lock()
	dir := o.cgroups[id]
	o.mu.Unlock()
	if dir == "" {
		found := map[uint64]string{}
		_ = filepath.WalkDir("/sys/fs/cgroup", func(path string, e fs.DirEntry, err error) error {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if err != nil {
				return fs.SkipDir
			}
			if !e.IsDir() {
				return nil
			}
			var s unix.Stat_t
			if unix.Stat(path, &s) == nil {
				found[s.Ino] = path
				if s.Ino == id {
					dir = path
				}
			}
			return nil
		})
		o.mu.Lock()
		for id, path := range found {
			o.cgroups[id] = path
		}
		o.mu.Unlock()
	}
	if dir == "" {
		return nil
	}
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
	return pids
}

func (o *Owners) holders(ctx context.Context, r socketRow) (platform.Owner, error) {
	if r.inode == 0 {
		return platform.Owner{}, os.ErrNotExist
	}
	target := "socket:[" + strconv.FormatUint(uint64(r.inode), 10) + "]"
	var result platform.Owner
	var found []holder
	seen := map[uint32]bool{}
	accept := func(pid uint32, fd string) error {
		live, err := processOwner(pid)
		if err != nil {
			return nil
		}
		if got, err := os.Readlink(fmt.Sprintf("/proc/%d/fd/%s", pid, fd)); err != nil || got != target {
			return nil
		}
		if result.AppID != "" && result.AppID != live.AppID {
			return platform.ErrAmbiguous
		}
		if result.AppID == "" {
			result = live
		}
		found = append(found, holder{pid, live.StartTime, fd})
		return nil
	}
	o.mu.Lock()
	cached := append([]holder(nil), o.cache[r.cookie]...)
	recent := append([]uint32(nil), o.recent[r.uid]...)
	o.mu.Unlock()
	// A cached inode association is evidence only after both the PID start time
	// and its live fd are checked. Other holders are still searched for conflicts.
	for _, h := range cached {
		if ctx.Err() != nil {
			break
		}
		if start, err := processStart(h.pid); err == nil && start == h.start {
			if err := accept(h.pid, h.fd); err != nil {
				return platform.Owner{}, err
			}
		}
	}
	var heavy []uint32
	scan := func(pid uint32, limited bool) error {
		if seen[pid] || ctx.Err() != nil {
			return nil
		}
		seen[pid] = true
		dir := fmt.Sprintf("/proc/%d/fd", pid)
		f, err := os.Open(dir)
		if err != nil {
			return nil
		}
		defer f.Close()
		// Readdirnames avoids sorting thousands of regular files. Check a
		// bounded slice per process first so one huge fd table cannot starve a
		// cross-uid holder near the end of /proc.
		count := 0
		for ctx.Err() == nil {
			fds, err := f.Readdirnames(64)
			for _, fd := range fds {
				if ctx.Err() != nil {
					break
				}
				got, e := os.Readlink(dir + "/" + fd)
				if e == nil && got == target {
					if e := accept(pid, fd); e != nil {
						return e
					}
				}
			}
			count += len(fds)
			if err != nil {
				break
			}
			if limited && count >= 256 {
				heavy = append(heavy, pid)
				break
			}
		}
		return nil
	}
	groups := o.cgroupPIDs(ctx, r.cgroup)
	for _, pids := range [][]uint32{recent, groups} {
		for _, pid := range pids {
			if err := scan(pid, true); err != nil {
				return platform.Owner{}, err
			}
		}
	}
	entries, _ := os.ReadDir("/proc")
	var sameUID, other []uint32
	for i := len(entries) - 1; i >= 0 && ctx.Err() == nil; i-- {
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
	slices.Sort(other)
	slices.Reverse(other)
	for _, pids := range [][]uint32{sameUID, other} {
		for _, pid := range pids {
			if err := scan(pid, true); err != nil {
				return platform.Owner{}, err
			}
		}
	}
	for _, pid := range heavy {
		delete(seen, pid)
		if err := scan(pid, false); err != nil {
			return platform.Owner{}, err
		}
	}
	if result.AppID == "" {
		if ctx.Err() != nil {
			return result, ctx.Err()
		}
		return result, os.ErrNotExist
	}
	result.Generation = r.generation()
	o.mu.Lock()
	if len(o.cache) >= 32768 {
		clear(o.cache)
	}
	o.cache[r.cookie] = found
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

func (o *Owners) Snapshot(ctx context.Context, keys []netip.AddrPort) (map[netip.AddrPort]platform.Owner, error) {
	rows := map[int][]socketRow{}
	for _, fam := range []int{unix.AF_INET, unix.AF_INET6} {
		need := false
		for _, k := range keys {
			if familyOf(k.Addr()) == fam {
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
	out := make(map[netip.AddrPort]platform.Owner, len(keys))
	for _, k := range keys {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		r, err := matchUDP(byPort[k.Port()], k)
		if err != nil {
			continue
		}
		o.mu.Lock()
		cached := append([]holder(nil), o.cache[r.cookie]...)
		o.mu.Unlock()
		var owner platform.Owner
		// Reconcile every cookie, plus revalidate recorded holders. A changed
		// holder is resolved afresh on the next datagram after closing the mapping.
		for _, h := range cached {
			start, err := processStart(h.pid)
			if err != nil || start != h.start {
				continue
			}
			link, err := os.Readlink(fmt.Sprintf("/proc/%d/fd/%s", h.pid, h.fd))
			if err != nil || link != "socket:["+strconv.FormatUint(uint64(r.inode), 10)+"]" {
				continue
			}
			v, err := processOwner(h.pid)
			if err != nil {
				continue
			}
			if owner.AppID != "" && owner.AppID != v.AppID {
				owner = platform.Owner{}
				break
			}
			owner = v
		}
		if owner.AppID != "" {
			owner.Generation = r.generation()
			out[k] = owner
		}
	}
	return out, nil
}
