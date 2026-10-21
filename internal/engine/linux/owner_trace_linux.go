//go:build linux

package linux

import (
	"context"
	"fmt"
	"github.com/AyoubAchour/net-switch/internal/engine/platform"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Bounded production diagnostics. Negative FD values are stages: -1 getdents,
// -2 scratch acquisition, -3 directory open, -4 stat, -5 seek.
// Eight failed scans survive beyond the ordinary completed-batch cache.
const descriptorTraceReads = 1024

// Wall-clock nanoseconds; FinishedNS stays 0 while the read is running.
type descriptorReadStamp struct {
	FD                    int64
	StartedNS, FinishedNS int64
}

// descriptorReads is a snapshot's own copy of its scan's reads, oldest first.
// Stats sends each read as a JSON array, its times in nanoseconds after the
// snapshot's EnqueuedNS:
//
//	[fd, start, finish]  a finished read
//	[fd, start]          a read still running when the snapshot was taken
//
// A read's wall-clock times are EnqueuedNS+start and EnqueuedNS+finish; an
// offset is negative only if the wall clock stepped back during the scan.
// Keyed objects with absolute times made eight failed and eight slow scans of
// 1024 reads exceed the control protocol's 1 MiB reply limit.
type descriptorReads struct {
	enqueuedNS int64
	stamps     []descriptorReadStamp
}

// MarshalJSON writes the list into one buffer, with no value per read.
func (r descriptorReads) MarshalJSON() ([]byte, error) {
	b := make([]byte, 0, 2+32*len(r.stamps))
	b = append(b, '[')
	for i, read := range r.stamps {
		if i > 0 {
			b = append(b, ',')
		}
		b = append(b, '[')
		b = strconv.AppendInt(b, read.FD, 10)
		b = append(b, ',')
		b = strconv.AppendInt(b, read.StartedNS-r.enqueuedNS, 10)
		if read.FinishedNS != 0 {
			b = append(b, ',')
			b = strconv.AppendInt(b, read.FinishedNS-r.enqueuedNS, 10)
		}
		b = append(b, ']')
	}
	return append(b, ']'), nil
}

type descriptorTrace struct {
	mu      sync.Mutex
	reads   []descriptorReadStamp
	omitted int
}

func (t *descriptorTrace) begin(fd int64) int {
	now := time.Now().UnixNano()
	t.mu.Lock()
	defer t.mu.Unlock()
	if len(t.reads) == descriptorTraceReads {
		t.omitted++
		return -1
	}
	t.reads = append(t.reads, descriptorReadStamp{FD: fd, StartedNS: now})
	return len(t.reads) - 1
}
func (t *descriptorTrace) end(index int) {
	if index < 0 {
		return
	}
	now := time.Now().UnixNano()
	t.mu.Lock()
	t.reads[index].FinishedNS = now
	t.mu.Unlock()
}

type descriptorFailure struct {
	job                 *descriptorBatch
	target              platform.Tuple
	requested, observed int64
	lookupDeadline      int64
	stage               uint32
	outcome             string
}
type descriptorScanSnapshot struct {
	Target                                                                      platform.Tuple
	PID                                                                         uint32
	Offset                                                                      int64
	OpenedFD                                                                    int64
	Limit                                                                       int
	Inline                                                                      bool
	RequestedNS, EnqueuedNS, WorkerStartedNS, DeadlineNS, FailedNS, CompletedNS int64
	LookupDeadlineNS                                                            int64
	QueueAtEnqueue, InFlightAtEnqueue, QueueAtStart, InFlightAtStart            int64
	Stage                                                                       string
	FailureStage                                                                string
	Outcome                                                                     string
	ObservedNS                                                                  int64
	Reads                                                                       descriptorReads `json:"ReadsRelativeToEnqueuedNS"`
	OmittedReads                                                                int
}

func descriptorStage(stage uint32) string {
	names := []string{"queued", "starting", "opening-proc", "reading-descriptors", "publishing-index", "completing", "done", "updating-process-window", "closing-proc"}
	return names[stage]
}
func (f *descriptorFailure) snapshot() descriptorScanSnapshot {
	j := f.job
	s := descriptorScanSnapshot{Target: f.target, PID: j.key.pid, Offset: j.key.offset, OpenedFD: j.openedFDPlusOne.Load() - 1, Limit: j.key.limit, Inline: j.inline,
		RequestedNS: f.requested, EnqueuedNS: j.queued.UnixNano(), WorkerStartedNS: j.startedNS.Load(), DeadlineNS: j.deadline.UnixNano(), LookupDeadlineNS: f.lookupDeadline, ObservedNS: f.observed, Outcome: f.outcome, CompletedNS: j.completedNS.Load(),
		QueueAtEnqueue: j.queueAtEnqueue, InFlightAtEnqueue: j.inFlightAtEnqueue, QueueAtStart: j.queueAtStart.Load(), InFlightAtStart: j.inFlightAtStart.Load(), Stage: descriptorStage(j.stage.Load()), FailureStage: descriptorStage(f.stage)}
	if f.outcome == "deadline" {
		s.FailedNS = f.observed
	} else {
		s.FailureStage = ""
	}
	// Copy under the scanner's lock; the reply encoder formats the copy later.
	j.trace.mu.Lock()
	s.Reads = descriptorReads{enqueuedNS: s.EnqueuedNS, stamps: append([]descriptorReadStamp(nil), j.trace.reads...)}
	s.OmittedReads = j.trace.omitted
	j.trace.mu.Unlock()
	return s
}

func observeDescriptorBatch(ctx context.Context, job *descriptorBatch, row socketRow, requested time.Time, outcome string) *descriptorFailure {
	event := &descriptorFailure{job: job, target: platform.Tuple{Source: row.local, Destination: row.remote}, requested: requested.UnixNano(), observed: time.Now().UnixNano(), stage: job.stage.Load(), outcome: outcome}
	if deadline, ok := ctx.Deadline(); ok {
		event.lookupDeadline = deadline.UnixNano()
	}
	return event
}

func (o *Owners) recordSlowBatch(ctx context.Context, job *descriptorBatch, row socketRow, requested time.Time) {
	if time.Since(job.queued) < time.Millisecond {
		return
	}
	sequence := o.batches.slowSequence.Add(1)
	o.batches.slow[(sequence-1)%uint64(len(o.batches.slow))].Store(observeDescriptorBatch(ctx, job, row, requested, "slow batch"))
}

func descriptorTableSize() (int, error) {
	data, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return 0, err
	}
	for _, line := range strings.Split(string(data), "\n") {
		if value, ok := strings.CutPrefix(line, "FDSize:"); ok {
			return strconv.Atoi(strings.TrimSpace(value))
		}
	}
	return 0, fmt.Errorf("/proc/self/status has no FDSize")
}
