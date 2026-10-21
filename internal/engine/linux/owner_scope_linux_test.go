//go:build linux

package linux

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"
)

func TestScopeReadReuseIsLimitedToOverlappingLookups(t *testing.T) {
	o := newTestOwners(t)
	const id = uint64(123)
	dir := t.TempDir()
	path := filepath.Join(dir, "cgroup.procs")
	if err := os.WriteFile(path, []byte("123\n"), 0600); err != nil {
		t.Fatal(err)
	}
	o.cgroupMu.Lock()
	o.cgroups[id] = dir
	o.cgroupMu.Unlock()
	requested := time.Now()
	if got := o.cgroupPIDs(context.Background(), id, requested); !slices.Equal(got, []uint32{123}) {
		t.Fatal(got)
	}
	if err := os.WriteFile(path, []byte("456\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if got := o.cgroupPIDs(context.Background(), id, requested); !slices.Equal(got, []uint32{123}) || o.sharedScopes.Load() != 1 {
		t.Fatalf("overlapping lookup: %v", got)
	}
	if got := o.cgroupPIDs(context.Background(), id, time.Now()); !slices.Equal(got, []uint32{456}) {
		t.Fatalf("later lookup reused stale membership: %v", got)
	}
	if o.sharedScopes.Load() != 1 {
		t.Fatal("later lookup was counted as a shared read")
	}
}
