package flows

import (
	"path/filepath"
	"testing"
)

func TestPersistedRevisionIsHistoryUntilStart(t *testing.T) {
	state := FileState{Path: filepath.Join(t.TempDir(), "engine-state.json"), SyncParent: func(string) error { return nil }}
	f := New(Defaults(), state)
	a, err := f.Apply(revision(1))
	if err != nil {
		t.Fatal(err)
	}
	history, err := state.History()
	if err != nil || *history != a {
		t.Fatal(history, err)
	}
	restart := New(Defaults(), state)
	if restart.Applied() != nil {
		t.Fatal("history loaded as live policy")
	}
}
func TestTCPGrowthReservesBeforeAllocation(t *testing.T) {
	l := Defaults()
	l.TCPBytes = DefaultTCP + (1 << 20)
	f := table(t, l)
	x := admit(t, f, "tcp", "known").(*ticket)
	if !x.Grow(2<<20, 1<<20) {
		t.Fatal("available bytes refused")
	}
	if x.Grow(2<<20, 2<<20) {
		t.Fatal("unreserved growth allowed")
	}
	if rx, tx := x.Buffers(); rx != 2<<20 || tx != 1<<20 {
		t.Fatal("failed reservation changed buffers")
	}
	x.Close()
	if f.Stats().TCPBytes != 0 {
		t.Fatal("growth reservation leaked")
	}
}
