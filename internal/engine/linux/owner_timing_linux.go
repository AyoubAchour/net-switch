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
	phaseDescriptors
	phaseValidation
	phaseMetadataExe
	phaseMetadataScratch
	phaseMetadataFlatpak
	phaseMetadataEnviron
	phaseMetadataRootOpen
	phaseMetadataInfoOpen
	phaseMetadataRootClose
	phaseMetadataStart
	phaseOther
	lookupPhases
)

var lookupPhaseNames = [lookupPhases]string{
	"index", "scope-map", "scope-scratch", "scope-open", "scope-stat",
	"scope-read", "scope-close", "scope-parse", "scope-rank", "process-open",
	"process-start", "process-close", "descriptor-batch-wait", "validation",
	"metadata-exe", "metadata-scratch", "metadata-flatpak", "metadata-environ",
	"metadata-root-open", "metadata-info-open", "metadata-root-close", "metadata-start", "other",
}

type lookupTiming struct {
	phases [lookupPhases]time.Duration
}

func (t *lookupTiming) add(phase lookupPhase, elapsed time.Duration) {
	if t != nil {
		t.phases[phase] += elapsed
	}
}

func (t *lookupTiming) metadataDuration() time.Duration {
	if t == nil {
		return 0
	}
	var total time.Duration
	for phase := phaseMetadataExe; phase <= phaseMetadataStart; phase++ {
		total += t.phases[phase]
	}
	return total
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
	fd, direct, err := openKernelFile(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NONBLOCK|unix.O_NOFOLLOW)
	timing.add(phaseScopeOpen, time.Since(started))
	if err != nil {
		return nil, err
	}
	defer func() {
		started := time.Now()
		closeKernelFile(fd, direct)
		timing.add(phaseScopeClose, time.Since(started))
	}()
	started = time.Now()
	err = regularKernelFile(fd, len(b), direct)
	timing.add(phaseScopeStat, time.Since(started))
	if err != nil {
		return nil, err
	}
	started = time.Now()
	read := unix.Read
	if direct && kernelScopePath(path) {
		read = readKernelData
	}
	data, err := readBoundedWith(fd, b, read)
	timing.add(phaseScopeRead, time.Since(started))
	return data, err
}
