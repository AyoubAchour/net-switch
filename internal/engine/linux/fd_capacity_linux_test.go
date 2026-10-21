//go:build linux

package linux

import (
	"errors"
	"math"
	"os"
	"os/exec"
	"runtime"
	"slices"
	"strconv"
	"testing"
	"time"

	"github.com/AyoubAchour/net-switch/internal/engine/flows"
	"golang.org/x/sys/unix"
)

// Each case runs in a new process so no earlier test has grown its table.
// Launchers/runtime initialization can leave different starting capacities;
// measure the actual boundary, then prove growth or its prevention there.
func freshDescriptorProcess(t *testing.T, name string) bool {
	t.Helper()
	if os.Getenv("NETSWITCH_FD_CHILD") == name {
		runtime.GOMAXPROCS(2)
		return true
	}
	cmd := exec.CommandContext(t.Context(), os.Args[0], "-test.run=^"+name+"$", "-test.v")
	cmd.Env = append(os.Environ(), "NETSWITCH_FD_CHILD="+name)
	output, err := cmd.CombinedOutput()
	t.Log(string(output))
	if err != nil {
		t.Fatal(err)
	}
	return false
}

func freshTableSize(t *testing.T) int {
	t.Helper()
	size, err := descriptorTableSize()
	if err != nil || size < 64 || size&(size-1) != 0 {
		t.Fatalf("fresh-process FD table precondition: %d %v", size, err)
	}
	t.Logf("fresh-process FD table=%d race-instrumented=%t", size, raceInstrumented)
	return size
}

// Fill every free descriptor below boundary and return the held duplicates.
func holdBelow(t *testing.T, boundary int) []int {
	t.Helper()
	seed, err := unix.Open("/dev/null", unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	held := []int{seed}
	t.Cleanup(func() {
		for _, fd := range held {
			unix.Close(fd)
		}
	})
	for seed != boundary-1 {
		fd, err := unix.FcntlInt(uintptr(seed), unix.F_DUPFD_CLOEXEC, 0)
		if err != nil {
			t.Fatal(err)
		}
		held = append(held, fd)
		if fd == boundary-1 {
			break
		}
		if fd >= boundary {
			t.Fatal("fixture crossed boundary before measured open")
		}
	}
	return held
}

// The cold reference: without a reservation, the proc fd directory open that
// crosses the initial table boundary grows the table inside the lookup.
func TestProcOpenAcrossDescriptorTableBoundary(t *testing.T) {
	if !freshDescriptorProcess(t, "TestProcOpenAcrossDescriptorTableBoundary") {
		return
	}
	before := freshTableSize(t)
	holdBelow(t, before)
	began := time.Now()
	cold, err := openProcDescriptors("/proc/self/fd")
	coldTime := time.Since(began)
	if err != nil {
		t.Fatal(err)
	}
	fd := cold.fd
	if fd != before {
		t.Fatalf("measured open did not cross the proven boundary: fd=%d size=%d", fd, before)
	}
	cold.Close()
	after, err := descriptorTableSize()
	if err != nil || after <= before {
		t.Fatalf("kernel table did not expand: %d -> %d (%v)", before, after, err)
	}
	began = time.Now()
	warm, err := openProcDescriptors("/proc/self/fd")
	warmTime := time.Since(began)
	if err != nil {
		t.Fatal(err)
	}
	if warm.fd != fd {
		t.Fatal("warm comparison did not reuse the same descriptor")
	}
	warm.Close()
	t.Logf("FD table %d -> %d; cold proc open fd=%d duration=%s exceeds-8ms=%t; same-fd warm open=%s", before, after, fd, coldTime, coldTime > 8*time.Millisecond, warmTime)
}

func TestDescriptorTargetBudget(t *testing.T) {
	linux := flows.Defaults()
	linux.Handshakes = 8192 // the Linux budget, whichever OS runs this case
	huge := flows.Limits{Flows: math.MaxInt, Handshakes: math.MaxInt, UDP: math.MaxInt}
	for _, c := range []struct {
		name   string
		limits flows.Limits
		soft   uint64
		want   int
	}{
		{"linux defaults unlimited", linux, unix.RLIM_INFINITY, 164864},
		{"linux defaults high limit", linux, 1 << 20, 164864},
		{"clamped to soft limit", linux, 65536, 65536},
		{"tiny limit", linux, 50, 50},
		{"one", linux, 1, 1},
		{"zero", linux, 0, 0},
		{"limit above kernel ceiling", linux, math.MaxUint64 - 1, 164864},
		{"saturating budgets", huge, unix.RLIM_INFINITY, kernelDescriptorCeiling},
		{"saturating budgets clamped", huge, 4096, 4096},
		{"negative budgets", flows.Limits{Flows: -1, Handshakes: -1, UDP: -1}, unix.RLIM_INFINITY, fixedDescriptors},
	} {
		if got := descriptorTarget(c.limits, c.soft); got != c.want {
			t.Errorf("%s: target %d, want %d", c.name, got, c.want)
		}
	}
	if kernelDescriptorCeiling != 2147483584 {
		t.Fatalf("kernel nr_open ceiling %d", kernelDescriptorCeiling)
	}
}

// An independent view of the open descriptors, from proc rather than our own
// bookkeeping. The listing's own directory descriptor appears in it.
func openDescriptors(t *testing.T) []int {
	t.Helper()
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}
	var fds []int
	for _, e := range entries {
		fd, err := strconv.Atoi(e.Name())
		if err != nil {
			t.Fatalf("proc fd entry %q", e.Name())
		}
		fds = append(fds, fd)
	}
	slices.Sort(fds)
	return fds
}

func lowestFree(t *testing.T) int {
	t.Helper()
	fd, err := unix.Eventfd(0, unix.EFD_CLOEXEC)
	if err != nil {
		t.Fatal(err)
	}
	if err := unix.Close(fd); err != nil {
		t.Fatal(err)
	}
	return fd
}

func requireClosed(t *testing.T, label string, fd int) {
	t.Helper()
	if fd < 0 {
		t.Fatalf("%s descriptor was never opened", label)
	}
	if _, err := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0); !errors.Is(err, unix.EBADF) {
		t.Fatalf("%s descriptor %d still open after the reservation returned: %v", label, fd, err)
	}
}

// Linux's alloc_fdtable rounding, for the log only.
func kernelTableFor(fd int) int {
	n := fd / 128
	p := 1
	for p < n+1 {
		p <<= 1
	}
	return p * 128
}

func TestReservedDescriptorTableCrossesBoundaryWithoutGrowth(t *testing.T) {
	if !freshDescriptorProcess(t, "TestReservedDescriptorTableCrossesBoundaryWithoutGrowth") {
		return
	}
	// The first proc read starts the runtime's poller, whose descriptors stay
	// open; take it before the descriptor snapshots below.
	initial := freshTableSize(t)
	var limit, limitAfter unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_NOFILE, &limit); err != nil {
		t.Fatal(err)
	}
	target := descriptorTarget(flows.Defaults(), limit.Cur)
	if limit.Cur > uint64(initial) && target <= initial {
		t.Fatalf("fixture already grew to %d before reservation target %d", initial, target)
	}
	free := lowestFree(t)
	listed := openDescriptors(t)

	r := prepareDescriptorTable(flows.Defaults())

	// Checked immediately: nothing else in this process opens descriptors, so
	// no background close can account for these.
	if target > initial {
		requireClosed(t, "duplicate", r.Duplicate)
		requireClosed(t, "source", r.Source)
	} else if r.Source != -1 || r.Duplicate != -1 {
		t.Fatalf("already-sized table opened reservation descriptors: %+v", r)
	}
	if r.Err != nil {
		t.Fatalf("reservation failed: %+v", r)
	}
	if err := unix.Getrlimit(unix.RLIMIT_NOFILE, &limitAfter); err != nil || limitAfter != limit {
		t.Fatalf("RLIMIT_NOFILE changed: %+v -> %+v (%v)", limit, limitAfter, err)
	}
	if r.Target != target || r.Limit != limit.Cur || r.Before != initial {
		t.Fatalf("reservation %+v; want target %d limit %d before %d", r, target, limit.Cur, initial)
	}
	size, err := descriptorTableSize()
	if err != nil || size != r.After || size < target {
		t.Fatalf("table %d (reported %d) below target %d: %v", size, r.After, target, err)
	}
	if target > initial && (r.Duplicate < target-1 || r.Duplicate >= size) {
		t.Fatalf("duplicate %d outside [%d, %d)", r.Duplicate, target-1, size)
	}
	if target > initial && r.Source != free {
		t.Fatalf("reservation source %d, lowest free was %d", r.Source, free)
	}
	if after := lowestFree(t); after != free {
		t.Fatalf("lowest free descriptor moved: %d -> %d", free, after)
	}
	if after := openDescriptors(t); !slices.Equal(after, listed) {
		t.Fatalf("open descriptors changed: %v -> %v", listed, after)
	}
	t.Logf("RLIMIT_NOFILE soft=%d hard=%d; target=%d; table %d -> %d (kernel rounding predicts %d); duplicate fd=%d source fd=%d",
		limit.Cur, limit.Max, target, r.Before, size, kernelTableFor(r.Duplicate), r.Duplicate, r.Source)

	if size <= initial {
		t.Skipf("RLIMIT_NOFILE %d leaves no room past the %d-entry boundary", limit.Cur, initial)
	}
	holdBelow(t, initial)
	began := time.Now()
	crossing, err := openProcDescriptors("/proc/self/fd")
	crossingTime := time.Since(began)
	if err != nil {
		t.Fatal(err)
	}
	fd := crossing.fd
	crossing.Close()
	if fd != initial {
		t.Fatalf("measured open did not cross the old boundary: fd=%d boundary=%d", fd, initial)
	}
	if grown, err := descriptorTableSize(); err != nil || grown != size {
		t.Fatalf("crossing the old boundary resized the reserved table: %d -> %d (%v)", size, grown, err)
	}
	began = time.Now()
	warm, err := openProcDescriptors("/proc/self/fd")
	warmTime := time.Since(began)
	if err != nil {
		t.Fatal(err)
	}
	if warm.fd != fd {
		t.Fatal("warm comparison did not reuse the same descriptor")
	}
	warm.Close()
	t.Logf("reserved table %d; proc open at fd=%d duration=%s exceeds-8ms=%t; same-fd repeat=%s", size, fd, crossingTime, crossingTime > 8*time.Millisecond, warmTime)
}

func TestWarmReservesDescriptorTable(t *testing.T) {
	if !freshDescriptorProcess(t, "TestWarmReservesDescriptorTable") {
		return
	}
	initial := freshTableSize(t)
	var limit unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_NOFILE, &limit); err != nil {
		t.Fatal(err)
	}
	o := NewOwners()
	defer o.Close()
	if err := o.Warm(t.Context()); err != nil {
		t.Fatal(err)
	}
	s := o.Stats().(lookupStats)
	target := descriptorTarget(flows.Defaults(), limit.Cur)
	if s.FDReserveError != "" || s.FDReserveTarget != target || s.FDReserveLimit != limit.Cur || s.FDReserveBefore != initial || s.FDReserveAfter < target || s.FDTableSize != s.FDReserveAfter {
		t.Fatalf("Warm reservation stats: target=%d limit=%d before=%d after=%d table=%d error=%q; want target %d limit %d",
			s.FDReserveTarget, s.FDReserveLimit, s.FDReserveBefore, s.FDReserveAfter, s.FDTableSize, s.FDReserveError, target, limit.Cur)
	}
	for _, fd := range openDescriptors(t) {
		if fd >= initial {
			t.Fatalf("Warm left descriptor %d open above the old boundary", fd)
		}
	}
	t.Logf("Warm reserved %d entries for target %d", s.FDReserveAfter, target)
}

func TestDescriptorReservationAlreadySized(t *testing.T) {
	if !freshDescriptorProcess(t, "TestDescriptorReservationAlreadySized") {
		return
	}
	before := freshTableSize(t)
	listed := openDescriptors(t)
	r := reserveDescriptorTable(before)
	if r.Err != nil || r.Before != before || r.After != before || r.Source != -1 || r.Duplicate != -1 {
		t.Fatalf("already-sized reservation did work or failed: %+v", r)
	}
	if after := openDescriptors(t); !slices.Equal(after, listed) {
		t.Fatalf("already-sized reservation changed open descriptors: %v -> %v", listed, after)
	}
}

// descriptorTarget never asks past the soft limit, so a refusal is driven
// here directly: the kernel rejects F_DUPFD at or above RLIMIT_NOFILE.
func TestRefusedReservationIsReportedAndLeavesNothingOpen(t *testing.T) {
	var limit unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_NOFILE, &limit); err != nil {
		t.Fatal(err)
	}
	if limit.Cur >= kernelDescriptorCeiling {
		t.Skipf("soft limit %d leaves no refusable target", limit.Cur)
	}
	before, err := descriptorTableSize()
	if err != nil {
		t.Fatal(err)
	}
	if before >= kernelDescriptorCeiling {
		t.Skipf("table size %d leaves no larger refusable target", before)
	}
	listed := openDescriptors(t)
	// A rounded table can already exceed a small soft limit. Prove this
	// attempt needs growth as well as exceeding the unchanged limit.
	target := max(int(limit.Cur), before) + 1
	r := reserveDescriptorTable(target)
	if !errors.Is(r.Err, unix.EINVAL) || r.Duplicate != -1 {
		t.Fatalf("refusal not reported: %+v", r)
	}
	requireClosed(t, "source", r.Source)
	if r.Before != before || r.After != before {
		t.Fatalf("refused reservation changed the table: %+v, was %d", r, before)
	}
	if after := openDescriptors(t); !slices.Equal(after, listed) {
		t.Fatalf("open descriptors changed: %v -> %v", listed, after)
	}
}
