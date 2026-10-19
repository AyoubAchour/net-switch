package engine

import (
	"errors"
	"fmt"
	"testing"
	"time"
)

func TestRefusedWith(t *testing.T) {
	err := fmt.Errorf("apply: %w", &Refusal{Code: RefusedStale, Message: "stale revision"})
	if !RefusedWith(err, RefusedStale) || RefusedWith(err, RefusedConflict) || RefusedWith(errors.New("stale revision"), RefusedStale) {
		t.Fatal("RefusedWith must match only a wrapped refusal with that code, never message text")
	}
}

func TestLookupMean(t *testing.T) {
	if (Stats{}).LookupMean() != 0 {
		t.Fatal("no lookups, no mean")
	}
	if got := (Stats{LookupCount: 4, LookupTime: 10 * time.Millisecond}).LookupMean(); got != 2500*time.Microsecond {
		t.Fatalf("mean of 10 ms over 4 lookups = %v", got)
	}
}
