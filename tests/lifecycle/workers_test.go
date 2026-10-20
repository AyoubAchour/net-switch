package lifecycle_test

import (
	"testing"
	"time"
)

type workerRef interface {
	id() uint32
	alive() bool
	suspend() error
	close()
}

func runningWorkers(t *testing.T, parent uint32, directory string) []workerRef {
	t.Helper()
	var refs []workerRef
	wait(t, "two live worker streams", 15*time.Second, func() bool {
		for _, ref := range refs {
			ref.close()
		}
		refs = findWorkers(t, parent, directory)
		return len(refs) >= 2
	})
	for _, ref := range refs {
		if !ref.alive() {
			t.Fatal("worker exited before fault injection")
		}
		t.Cleanup(ref.close)
	}
	return refs
}
func workersGone(t *testing.T, refs []workerRef, duration time.Duration) {
	t.Helper()
	wait(t, "owned workers exited", duration, func() bool {
		for _, ref := range refs {
			if ref.alive() {
				return false
			}
		}
		return true
	})
}
