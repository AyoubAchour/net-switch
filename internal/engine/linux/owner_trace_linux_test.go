//go:build linux

package linux

import (
	"context"
	"encoding/json"
	"runtime"
	"slices"
	"sync"
	"testing"
	"time"
)

func TestDescriptorTraceDistinguishesQueueFromBlockedRead(t *testing.T) {
	row, _, _, key, _ := sharedBatchSocket(t)
	o := newTestOwners(t)
	processBuffers.mu.Lock()
	unlock := sync.OnceFunc(processBuffers.mu.Unlock)
	defer unlock()
	requested := time.Now()
	job, err := o.descriptorBatch(context.Background(), key, requested, false)
	if err != nil {
		t.Fatal(err)
	}
	until := time.Now().Add(time.Second)
	for {
		blocked := false
		job.trace.mu.Lock()
		for _, read := range job.trace.reads {
			blocked = blocked || (read.FD == -2 && read.StartedNS > 0 && read.FinishedNS == 0)
		}
		job.trace.mu.Unlock()
		if blocked {
			break
		}
		if time.Now().After(until) {
			t.Fatal("fixture never blocked inside scratch acquisition")
		}
		runtime.Gosched()
	}
	o.recordBatchWait(context.Background(), job, row, requested)
	failure := o.batches.failures[0].Load()
	before := failure.snapshot()
	if before.WorkerStartedNS < before.EnqueuedNS || before.QueueAtEnqueue != 0 || before.InFlightAtStart < 1 || before.CompletedNS != 0 || before.Target.Source != row.local {
		t.Fatalf("queued versus in-flight evidence missing: %+v", before)
	}
	unlock()
	select {
	case <-job.done:
	case <-time.After(time.Second):
		t.Fatal("read did not complete after the fixture released scratch")
	}
	after := failure.snapshot()
	if after.CompletedNS < after.WorkerStartedNS {
		t.Fatal("completion timestamp missing")
	}
	for _, read := range after.Reads.stamps {
		if read.FinishedNS < read.StartedNS {
			t.Fatalf("finished read has no matching timestamp: %+v", read)
		}
	}
	if before.Reads.stamps[len(before.Reads.stamps)-1].FinishedNS != 0 {
		t.Fatal("later completion mutated the earlier snapshot")
	}
	// On the wire the blocked scratch acquisition stays open: [-2, start].
	b, err := json.Marshal(before)
	if err != nil {
		t.Fatal(err)
	}
	var wire wireScan
	if err := json.Unmarshal(b, &wire); err != nil {
		t.Fatal(err)
	}
	last := wire.ReadsRelativeToEnqueuedNS[len(wire.ReadsRelativeToEnqueuedNS)-1]
	if !slices.Equal(wireReads(t, wire), before.Reads.stamps) || len(last) != 2 || last[0] != -2 {
		t.Fatalf("blocked read changed on the wire: %s", b)
	}
	t.Logf("queue=%d inflight=%d; blocked stage recorded before completion; %d read/stage pairs", before.QueueAtEnqueue, before.InFlightAtStart, len(after.Reads.stamps))
}

// Round 6: stamping every descriptor read was 27% of the engine's allocation
// at the TCP cap. Fast reads are now only counted; slow reads and the read
// still running keep their stamps, so a stalled read stays visible.
func TestDescriptorTraceStampsOnlySlowAndRunningReads(t *testing.T) {
	job := &descriptorBatch{queued: time.Now(), deadline: time.Now().Add(time.Second)}
	stage := job.trace.begin(-3)
	job.trace.end(stage)
	if allocs := testing.AllocsPerRun(1000, func() {
		started := time.Now()
		job.trace.reading(7, started)
		job.trace.read(7, started)
	}); allocs != 0 {
		t.Fatalf("a fast descriptor read allocated %.1f times", allocs)
	}
	slowStart := time.Now().Add(-2 * descriptorSlowRead)
	job.trace.reading(9, slowStart)
	job.trace.read(9, slowStart)
	running := time.Now()
	job.trace.reading(11, running)
	f := &descriptorFailure{job: job, outcome: "deadline"}
	s := f.snapshot()
	reads := s.Reads.stamps
	if len(reads) != 3 || reads[0].FD != -3 || reads[1].FD != 9 || reads[1].FinishedNS-reads[1].StartedNS < int64(descriptorSlowRead) ||
		reads[2] != (descriptorReadStamp{FD: 11, StartedNS: running.UnixNano()}) {
		t.Fatalf("want the stage, the slow read and the running read, got %+v", reads)
	}
	// Fast reads from AllocsPerRun (1000 plus its warm-up run) and the slow one.
	if s.DescriptorReads != 1002 || s.DescriptorReadNS < int64(2*descriptorSlowRead) || s.SlowReadNS != int64(descriptorSlowRead) {
		t.Fatalf("read counters: %d reads, %d ns, threshold %d", s.DescriptorReads, s.DescriptorReadNS, s.SlowReadNS)
	}
	job.trace.read(11, running)
	if after := f.snapshot().Reads.stamps; len(after) != 2 {
		t.Fatalf("a finished fast read stayed visible as running: %+v", after)
	}
	if len(s.Reads.stamps) != 3 {
		t.Fatal("a later read changed an earlier snapshot")
	}
}

func TestDescriptorTraceAndFailureHistoryAreBounded(t *testing.T) {
	o := newTestOwners(t)
	job := &descriptorBatch{queued: time.Now(), deadline: time.Now().Add(time.Second)}
	for i := 0; i < descriptorTraceReads+10; i++ {
		index := job.trace.begin(int64(i))
		job.trace.end(index)
	}
	for range 20 {
		o.recordBatchWait(context.Background(), job, socketRow{}, time.Now())
	}
	if len(job.trace.reads) != descriptorTraceReads || job.trace.omitted != 10 {
		t.Fatal("per-scan trace bound failed")
	}
	count := 0
	for i := range o.batches.failures {
		if o.batches.failures[i].Load() != nil {
			count++
		}
	}
	if count != 8 {
		t.Fatal("failure history is not bounded to eight scans")
	}
}
