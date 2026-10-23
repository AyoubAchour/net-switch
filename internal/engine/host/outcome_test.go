package host

import (
	"context"
	"errors"
	"testing"

	"github.com/AyoubAchour/net-switch/internal/journal"
)

type outcomeLock func(context.Context) (func() error, error)

func (f outcomeLock) Acquire(ctx context.Context) (func() error, error) { return f(ctx) }

func TestRecoveryOutcomeIncludesFinalReleaseFailure(t *testing.T) {
	held, reported := false, false
	late := errors.New("final native lock close failed")
	lock := outcomeLock(func(context.Context) (func() error, error) {
		if held {
			t.Fatal("recursive ownership acquisition")
		}
		held = true
		return func() error { held = false; return late }, nil
	})
	err := Recover(context.Background(), lock, func(borrowed journal.Locker) error {
		if !held {
			t.Fatal("cleanup ran without native ownership")
		}
		release, err := borrowed.Acquire(context.Background())
		if err != nil {
			return err
		}
		return release()
	}, func() (func(error) error, error) {
		if !held {
			t.Fatal("instance captured outside ownership lock")
		}
		return func(err error) error {
			reported = true
			if held || !errors.Is(err, late) {
				t.Fatal("premature successful recovery outcome", held, err)
			}
			return nil
		}, nil
	})
	if !reported || !errors.Is(err, late) {
		t.Fatal(reported, err)
	}
}

func TestRecoveryCannotReportForAnotherLiveOwner(t *testing.T) {
	busy := errors.New("native ownership still held")
	err := Recover(context.Background(), outcomeLock(func(context.Context) (func() error, error) { return nil, busy }),
		func(journal.Locker) error { t.Fatal("cleanup without ownership"); return nil },
		func() (func(error) error, error) { t.Fatal("outcome touched before ownership"); return nil, nil })
	if !errors.Is(err, busy) {
		t.Fatal(err)
	}
}
