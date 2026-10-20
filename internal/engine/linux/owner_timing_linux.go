//go:build linux

package linux

import (
	"sync/atomic"
	"time"

	"golang.org/x/sys/unix"
)

type lookupPhase uint8

const (
	phaseIndex lookupPhase = iota
	phaseScopeMap
	phaseScopeScratch
	phaseScopeOpen
	phaseScopeStat
	phaseScopeRead
	phaseScopeClose
	phaseScopeParse
	phaseRank
	phaseProcessOpen
	phaseProcessStart
	phaseProcessClose
	phaseScannerWait
	phaseDescriptors
	phaseValidation
	phaseOther
	lookupPhases
)

var lookupPhaseNames = [lookupPhases]string{
	"index", "scope-map", "scope-scratch", "scope-open", "scope-stat",
	"scope-read", "scope-close", "scope-parse", "scope-rank", "process-open",
	"process-start", "process-close", "scanner-wait", "descriptors", "validation", "other",
}

type lookupTiming struct {
	phases        [lookupPhases]time.Duration
	waitRequested time.Duration
	waitMaximum   time.Duration
}

func (t *lookupTiming) add(phase lookupPhase, elapsed time.Duration) {
	if t != nil {
		t.phases[phase] += elapsed
	}
}

type lookupPhaseCounter struct {
	count, largest, total, maximum atomic.Uint64
}

type lookupPhaseStat struct {
	Count, Largest, TotalNanos, MaxNanos uint64
}

func (o *Owners) recordHolderTimeout(t lookupTiming, elapsed time.Duration) {
	var accounted time.Duration
	for _, duration := range t.phases {
		accounted += duration
	}
	t.phases[phaseOther] += max(0, elapsed-accounted)
	largest := phaseOther
	for phase, duration := range t.phases {
		if duration > t.phases[largest] {
			largest = lookupPhase(phase)
		}
		if duration <= 0 {
			continue
		}
		counter := &o.timeoutPhases[phase]
		nanos := uint64(duration)
		counter.count.Add(1)
		counter.total.Add(nanos)
		recordLookupMaximum(&counter.maximum, nanos)
	}
	o.timeoutPhases[largest].largest.Add(1)
	o.timeoutWaitRequested.Add(uint64(t.waitRequested))
	recordLookupMaximum(&o.timeoutWaitMaximum, uint64(t.waitMaximum))
	o.holderTimeouts.Add(1)
}

func recordLookupMaximum(counter *atomic.Uint64, value uint64) {
	for previous := counter.Load(); value > previous; previous = counter.Load() {
		if counter.CompareAndSwap(previous, value) {
			return
		}
	}
}

// Keep the same bounded regular-file read as readInto, but distinguish kernel
// open/stat/read/close delays. Only failed lookups publish these measurements;
// there is no per-operation log, sample list, or shared hot-path timing lock.
func readScopeInto(path string, b []byte, timing *lookupTiming) ([]byte, error) {
	started := time.Now()
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NONBLOCK|unix.O_NOFOLLOW, 0)
	timing.add(phaseScopeOpen, time.Since(started))
	if err != nil {
		return nil, err
	}
	defer func() {
		started := time.Now()
		unix.Close(fd)
		timing.add(phaseScopeClose, time.Since(started))
	}()
	started = time.Now()
	err = regularFile(fd, len(b))
	timing.add(phaseScopeStat, time.Since(started))
	if err != nil {
		return nil, err
	}
	started = time.Now()
	data, err := readBounded(fd, b)
	timing.add(phaseScopeRead, time.Since(started))
	return data, err
}
