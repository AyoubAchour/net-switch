package engine

import (
	"errors"
	"fmt"
	"testing"
	"time"
)

func TestHistogram(t *testing.T) {
	bounds := []int64{1000, 5000, 10000}
	before := Histogram{BoundsMicros: bounds, Counts: []int64{10, 0, 0, 0}}
	after := Histogram{BoundsMicros: bounds, Counts: []int64{10, 90, 8, 2}}
	phase, err := after.Sub(before)
	if err != nil {
		t.Fatal(err)
	}
	if phase.Total() != 100 {
		t.Fatalf("phase has %d observations, want 100", phase.Total())
	}
	if p50, ok := phase.Quantile(0.5); !ok || p50 != 5*time.Millisecond {
		t.Errorf("p50 = %v %v, want 5ms", p50, ok)
	}
	if p95, ok := phase.Quantile(0.95); !ok || p95 != 10*time.Millisecond {
		t.Errorf("p95 = %v %v, want 10ms", p95, ok)
	}
	if _, ok := phase.Quantile(0.99); ok {
		t.Error("p99 lies above the last bound and must not be reported as known")
	}
	if _, ok := (Histogram{BoundsMicros: bounds, Counts: make([]int64, 4)}).Quantile(0.95); ok {
		t.Error("an empty histogram has no quantile")
	}
	if _, err := before.Sub(after); err == nil {
		t.Error("counts going down must be an error")
	}
}

func TestRevisionHashAndRefusals(t *testing.T) {
	a := Config{Lines: []Line{{ID: "a", Interface: "eth-a"}}, Policy: Policy{Shares: map[LineID]float64{"b": 0.3, "a": 0.7}}}
	b := Config{Lines: []Line{{ID: "a", Interface: "eth-a"}}, Policy: Policy{Shares: map[LineID]float64{"a": 0.7, "b": 0.3}}}
	if RevisionHash(a) != RevisionHash(b) {
		t.Fatal("the same config must hash the same")
	}
	b.Policy.IPv6 = true
	if RevisionHash(a) == RevisionHash(b) {
		t.Fatal("different configs must hash differently")
	}
	err := fmt.Errorf("apply: %w", &Refusal{Code: RefusedStale, Message: "n 3 < 4"})
	if !RefusedWith(err, RefusedStale) || RefusedWith(err, RefusedConflict) || RefusedWith(errors.New("x"), RefusedStale) {
		t.Fatal("RefusedWith must match only the wrapped code")
	}
}
