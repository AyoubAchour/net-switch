//go:build linux

package linux

import (
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

type descriptorReadStamp struct {
	FD                    int64
	StartedNS, FinishedNS int64
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
	job               *descriptorBatch
	target            platform.Tuple
	requested, failed int64
	lookupDeadline    int64
	stage             uint32
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
	Reads                                                                       []descriptorReadStamp
	OmittedReads                                                                int
}

func descriptorStage(stage uint32) string {
	names := []string{"queued", "starting", "opening-proc", "reading-descriptors", "publishing-index", "completing", "done", "updating-process-window", "closing-proc"}
	return names[stage]
}
func (f *descriptorFailure) snapshot() descriptorScanSnapshot {
	j := f.job
	s := descriptorScanSnapshot{Target: f.target, PID: j.key.pid, Offset: j.key.offset, OpenedFD: j.openedFDPlusOne.Load() - 1, Limit: j.key.limit, Inline: j.inline,
		RequestedNS: f.requested, EnqueuedNS: j.queued.UnixNano(), WorkerStartedNS: j.startedNS.Load(), DeadlineNS: j.deadline.UnixNano(), LookupDeadlineNS: f.lookupDeadline, FailedNS: f.failed, CompletedNS: j.completedNS.Load(),
		QueueAtEnqueue: j.queueAtEnqueue, InFlightAtEnqueue: j.inFlightAtEnqueue, QueueAtStart: j.queueAtStart.Load(), InFlightAtStart: j.inFlightAtStart.Load(), Stage: descriptorStage(j.stage.Load()), FailureStage: descriptorStage(f.stage)}
	j.trace.mu.Lock()
	s.Reads = append([]descriptorReadStamp(nil), j.trace.reads...)
	s.OmittedReads = j.trace.omitted
	j.trace.mu.Unlock()
	return s
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
