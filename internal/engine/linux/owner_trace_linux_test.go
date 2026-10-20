//go:build linux

package linux

import (
	"context"
	"runtime"
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
	for _, read := range after.Reads {
		if read.FinishedNS < read.StartedNS {
			t.Fatalf("finished read has no matching timestamp: %+v", read)
		}
	}
	if before.Reads[len(before.Reads)-1].FinishedNS != 0 {
		t.Fatal("later completion mutated the earlier snapshot")
	}
	t.Logf("queue=%d inflight=%d; blocked stage recorded before completion; %d read/stage pairs", before.QueueAtEnqueue, before.InFlightAtStart, len(after.Reads))
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
