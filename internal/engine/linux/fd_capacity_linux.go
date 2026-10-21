//go:build linux

package linux

import (
	"errors"
	"fmt"
	"math"

	"github.com/AyoubAchour/net-switch/internal/engine/flows"
	"golang.org/x/sys/unix"
)

// The kernel grows a descriptor table only when it allocates a descriptor at
// or beyond the table's end. Growth of a table shared by several threads waits
// for an RCU grace period, and every allocation racing it waits for the resize.
// Traffic used to pay that inside a deadline-bound owner lookup:
// proc's fd directory open was the descriptor that crossed 64, then 128, ...
// Growing the table once before capture moves that wait to startup.
//
// Descriptors are always allocated at the lowest free number, so the highest
// number ever used is below the peak count held at once. Under its budgets
// the engine holds:
//   - one host socket per admitted flow; Flows already includes UDP sessions;
//   - per pending owner lookup, at most four: the pinned proc fd directory plus
//     the root, .flatpak-info and reopened descriptors of the Flatpak identity
//     read. sock_diag connections return to their pool before holder scans.
//     Lookups run only for admitted handshakes and UDP sessions;
//   - fixed descriptors (TUN, epoll, journal, the idle sock_diag pool, echo
//     slots), control connections and transient closes, within 1,024.
//
// The 1,024 is operational headroom, not a ceiling: registered control clients
// are capped at four, but accepted connections awaiting registration can
// transiently accumulate, so the table can still grow later. This only
// takes the growth the budgets predict off the lookup path.
//
// With the Linux defaults that is 65,536 + 4*(8,192+16,384) + 1,024 = 164,864,
// which the kernel rounds to a 262,144-entry table (about 2 MiB of kernel
// memory). The table is never shrunk; forked children copy only the range
// that is open, and the reservation leaves nothing open up there.
const (
	lookupDescriptors = 4
	fixedDescriptors  = 1024
	// fcntl passes its argument to the kernel as an int; the kernel's own
	// nr_open ceiling is INT_MAX rounded down to a 64-bit word.
	kernelDescriptorCeiling = math.MaxInt32 &^ 63
)

type descriptorReservation struct {
	Target        int
	Limit         uint64 // RLIMIT_NOFILE soft limit; RLIM_INFINITY when unlimited
	Before, After int    // FDSize from /proc/self/status, 0 when unreadable
	// Descriptor numbers used and closed before return; -1 when not opened.
	Source, Duplicate int
	Err               error
}

func saturatingAdd(a, b uint64) uint64 {
	if a > math.MaxUint64-b {
		return math.MaxUint64
	}
	return a + b
}

func nonNegative(n int) uint64 {
	if n < 0 {
		return 0
	}
	return uint64(n)
}

// descriptorTarget is the table capacity the engine's budgets can use, never
// more than the process may open. It never asks for a higher limit.
func descriptorTarget(l flows.Limits, soft uint64) int {
	lookups := saturatingAdd(nonNegative(l.Handshakes), nonNegative(l.UDP))
	pending := uint64(math.MaxUint64)
	if lookups <= math.MaxUint64/lookupDescriptors {
		pending = lookups * lookupDescriptors
	}
	need := saturatingAdd(saturatingAdd(nonNegative(l.Flows), pending), fixedDescriptors)
	if soft != unix.RLIM_INFINITY {
		need = min(need, soft)
	}
	return int(min(need, kernelDescriptorCeiling))
}

// prepareDescriptorTable sizes the process's own descriptor table for l. It
// changes no limit or OS setting and keeps no descriptor open. Failure only
// leaves growth where it was, so the caller reports it and continues.
func prepareDescriptorTable(l flows.Limits) descriptorReservation {
	var limit unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_NOFILE, &limit); err != nil {
		r := descriptorReservation{Source: -1, Duplicate: -1, Err: fmt.Errorf("read RLIMIT_NOFILE: %w", err)}
		r.Before, _ = descriptorTableSize()
		r.After = r.Before
		return r
	}
	r := reserveDescriptorTable(descriptorTarget(l, limit.Cur))
	r.Limit = limit.Cur
	return r
}

// reserveDescriptorTable grows the table to at least target entries by
// duplicating a private descriptor to target-1 and closing that duplicate.
// The open and fcntl are ordinary scheduling syscalls: they can wait for the
// resize's RCU grace period.
func reserveDescriptorTable(target int) (r descriptorReservation) {
	r = descriptorReservation{Target: target, Source: -1, Duplicate: -1}
	before, sizeErr := descriptorTableSize()
	r.Before = before
	defer func() {
		r.After, sizeErr = descriptorTableSize()
		switch {
		case sizeErr != nil:
			r.Err = errors.Join(r.Err, fmt.Errorf("read descriptor table size: %w", sizeErr))
		case r.Err == nil && r.After < target:
			r.Err = fmt.Errorf("descriptor table has %d entries after reserving %d", r.After, target)
		}
	}()
	if target <= 0 || (sizeErr == nil && before >= target) {
		return r
	}
	// An eventfd is owned by this process and resolves no path, so the
	// reservation trusts no filesystem and runs no device open handler.
	source, err := unix.Eventfd(0, unix.EFD_CLOEXEC|unix.EFD_NONBLOCK)
	if err != nil {
		r.Err = fmt.Errorf("open reservation source: %w", err)
		return r
	}
	r.Source = source
	duplicate, err := unix.FcntlInt(uintptr(source), unix.F_DUPFD_CLOEXEC, target-1)
	if err != nil {
		r.Err = fmt.Errorf("reserve descriptor table to %d: %w", target, err)
	} else {
		r.Duplicate = duplicate
		if err := unix.Close(duplicate); err != nil {
			r.Err = fmt.Errorf("close reservation descriptor %d: %w", duplicate, err)
		}
	}
	if err := unix.Close(source); err != nil {
		r.Err = errors.Join(r.Err, fmt.Errorf("close reservation source %d: %w", source, err))
	}
	return r
}
