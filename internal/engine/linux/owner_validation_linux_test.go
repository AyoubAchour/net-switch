//go:build linux

package linux

import (
	"context"
	"os"
	"testing"
	"time"
)

func TestSharedMetadataMustBeginAfterTheDescriptorCheck(t *testing.T) {
	o := newTestOwners(t)
	pid := uint32(os.Getpid())
	start, err := processStart(pid)
	if err != nil {
		t.Fatal(err)
	}
	v := &ownerValidation{pid: pid, start: start}
	checked := time.Now()
	first, err := v.resolve(context.Background(), checked, o)
	if err != nil || first.PID != pid || first.StartTime != start || first.AppID == "" {
		t.Fatalf("real process validation: %+v %v", first, err)
	}
	shared, err := v.resolve(context.Background(), checked, o)
	if err != nil || shared != first || o.metadataPasses.Load() != 1 || o.sharedMetadata.Load() != 1 {
		t.Fatalf("overlapping validation was not shared: %+v %v", shared, err)
	}
	if _, err := v.resolve(context.Background(), time.Now(), o); err != nil {
		t.Fatal(err)
	}
	if o.metadataPasses.Load() != 2 {
		t.Fatal("a later lookup reused metadata from before its descriptor check")
	}
	wrong := &ownerValidation{pid: pid, start: start + 1}
	if owner, err := wrong.resolve(context.Background(), time.Now(), o); err == nil || owner.AppID != "" {
		t.Fatalf("wrong PID incarnation was accepted: %+v %v", owner, err)
	}
}

func TestMetadataWaitHonorsTheOriginalLookupDeadline(t *testing.T) {
	o := newTestOwners(t)
	blocked := make(chan struct{})
	v := &ownerValidation{running: blocked}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if owner, err := v.resolve(ctx, time.Now(), o); err != context.DeadlineExceeded || owner.AppID != "" {
		t.Fatalf("expired metadata wait: %+v %v", owner, err)
	}
	if o.metadataPasses.Load() != 0 {
		t.Fatal("cancelled lookup started a metadata read")
	}
}
