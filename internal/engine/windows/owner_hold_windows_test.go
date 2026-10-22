//go:build windows

package winengine

import (
	"context"
	"encoding/binary"
	"errors"
	"net/netip"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/AyoubAchour/net-switch/internal/engine/platform"
	"github.com/AyoubAchour/net-switch/internal/winclock"
	"golang.org/x/sys/windows"
)

// tcp4Table builds a MIB_TCPTABLE_OWNER_PID with one SYN_SENT row per tuple.
func tcp4Table(pid uint32, tuples ...platform.Tuple) []byte {
	b := make([]byte, 4+24*len(tuples))
	binary.LittleEndian.PutUint32(b, uint32(len(tuples)))
	for i, tuple := range tuples {
		r := b[4+24*i:]
		binary.LittleEndian.PutUint32(r, 3) // MIB_TCP_STATE_SYN_SENT
		source, destination := tuple.Source.Addr().As4(), tuple.Destination.Addr().As4()
		copy(r[4:8], source[:])
		binary.BigEndian.PutUint16(r[8:], tuple.Source.Port())
		copy(r[12:16], destination[:])
		binary.BigEndian.PutUint16(r[16:], tuple.Destination.Port())
		binary.LittleEndian.PutUint32(r[20:], pid)
	}
	return b
}

// slowTables makes every IPv4 read take delay and return rows; IPv6 reads
// return an empty table after the same delay.
func slowTables(o *Owners, delay func() time.Duration, rows func() []byte) {
	o.readTCP = func(ctx context.Context, family uint32, _ *[]uint64) ([]byte, error) {
		winclock.System.Wait(context.Background(), delay())
		if family == windows.AF_INET6 {
			return []byte{0, 0, 0, 0}, nil
		}
		return rows(), nil
	}
}

var holdTuple = platform.Tuple{Source: netip.MustParseAddrPort("10.0.0.2:40000"), Destination: netip.MustParseAddrPort("192.0.2.9:443")}

func timedLookup(o *Owners, ctx context.Context, tuple platform.Tuple) (platform.Owner, error, time.Duration) {
	start := winclock.Now()
	owner, err := o.TCP(ctx, tuple)
	return owner, err, winclock.Since(start)
}

// Spec 5.6, "Under overload": a read that started after the SYN and is still
// running at 50 ms holds the SYN until it finishes, up to 250 ms in total.
func TestOwnerOverloadHold(t *testing.T) {
	pid := uint32(os.Getpid())
	t.Run("a slow fresh read is waited for and finds the owner", func(t *testing.T) {
		o := NewOwners()
		slowTables(o, func() time.Duration { return 120 * time.Millisecond }, func() []byte { return tcp4Table(pid, holdTuple) })
		owner, err, took := timedLookup(o, context.Background(), holdTuple)
		if err != nil || owner.PID != pid {
			t.Fatalf("held lookup: %+v %v after %v", owner, err, took)
		}
		stats := o.Stats()
		if took < 100*time.Millisecond || took >= ownerOverloadHold || stats.TCPHolds != 1 || stats.TCPHeldFound != 1 {
			t.Fatalf("took %v holds %d found %d", took, stats.TCPHolds, stats.TCPHeldFound)
		}
	})
	t.Run("the hold ends at 250 ms in total", func(t *testing.T) {
		o := NewOwners()
		slowTables(o, func() time.Duration { return 400 * time.Millisecond }, func() []byte { return tcp4Table(pid, holdTuple) })
		_, err, took := timedLookup(o, context.Background(), holdTuple)
		if !errors.Is(err, context.DeadlineExceeded) || took < ownerOverloadHold || took > ownerOverloadHold+60*time.Millisecond {
			t.Fatalf("over-long read: %v after %v", err, took)
		}
		if failures := o.Stats().Failures; len(failures) == 0 {
			t.Fatal("the timed-out hold left no failure record")
		}
	})
	t.Run("a held read without the row is unknown, with no retries", func(t *testing.T) {
		o := NewOwners()
		var mu sync.Mutex
		reads := 0
		slowTables(o, func() time.Duration { mu.Lock(); reads++; mu.Unlock(); return 70 * time.Millisecond }, func() []byte { return tcp4Table(pid) })
		_, err, took := timedLookup(o, context.Background(), holdTuple)
		if err == nil || took > ownerOverloadHold+60*time.Millisecond {
			t.Fatalf("missing row: %v after %v", err, took)
		}
		mu.Lock()
		defer mu.Unlock()
		// The IPv4 read, then the IPv6 fallback for mapped sockets; no retry round.
		if reads > 2 {
			t.Fatalf("%d reads after the hold", reads)
		}
	})
	t.Run("fast reads keep the normal path", func(t *testing.T) {
		o := NewOwners()
		slowTables(o, func() time.Duration { return 5 * time.Millisecond }, func() []byte { return tcp4Table(pid, holdTuple) })
		owner, err, took := timedLookup(o, context.Background(), holdTuple)
		if err != nil || owner.PID != pid || took >= ownerLookupBound || o.Stats().TCPHolds != 0 {
			t.Fatalf("fast lookup: %+v %v after %v holds %d", owner, err, took, o.Stats().TCPHolds)
		}
	})
	// Spec 5.6, "No fresh read in flight at 50 ms": a lookup that joined a
	// slow read started before its SYN gets one fresh read at its bound, and
	// every SYN waiting at its bound shares that one read.
	t.Run("a slow read from before the SYN gets one shared fresh read at 50 ms", func(t *testing.T) {
		o := NewOwners()
		var mu sync.Mutex
		reads := 0
		late := make([]platform.Tuple, 5)
		for i := range late {
			late[i] = platform.Tuple{Source: netip.AddrPortFrom(holdTuple.Source.Addr(), uint16(40001+i)), Destination: holdTuple.Destination}
		}
		slowTables(o, func() time.Duration {
			mu.Lock()
			defer mu.Unlock()
			reads++
			if reads == 1 {
				return 200 * time.Millisecond
			}
			return 40 * time.Millisecond
		}, func() []byte { return tcp4Table(pid, append([]platform.Tuple{holdTuple}, late...)...) })
		early := make(chan error, 1)
		go func() { _, err := o.TCP(context.Background(), holdTuple); early <- err }()
		winclock.System.Wait(context.Background(), 20*time.Millisecond)
		// Each of these joins the 200 ms read that started before it. The
		// first to reach its 50 ms bound starts a 40 ms read; the others,
		// reaching theirs while it runs, join it.
		type outcome struct {
			owner platform.Owner
			err   error
			took  time.Duration
		}
		results := make(chan outcome, len(late))
		for _, tuple := range late {
			go func() {
				owner, err, took := timedLookup(o, context.Background(), tuple)
				results <- outcome{owner, err, took}
			}()
			winclock.System.Wait(context.Background(), 2*time.Millisecond)
		}
		for range late {
			r := <-results
			if r.err != nil || r.owner.PID != pid || r.took < ownerLookupBound || r.took >= ownerOverloadHold {
				t.Fatalf("late SYN: %+v %v after %v", r.owner, r.err, r.took)
			}
		}
		if err := <-early; err != nil {
			t.Fatalf("the lookup whose own read was slow should have been held: %v", err)
		}
		stats := o.Stats()
		mu.Lock()
		defer mu.Unlock()
		if stats.TCPHoldReads != 1 || reads != 2 || stats.TCPHeldFound != uint64(len(late))+1 {
			t.Fatalf("fresh reads started %d, table reads %d, held found %d", stats.TCPHoldReads, reads, stats.TCPHeldFound)
		}
	})
	t.Run("a found owner whose identity step crosses 50 ms is kept", func(t *testing.T) {
		o := NewOwners()
		slowTables(o, func() time.Duration { return 40 * time.Millisecond }, func() []byte { return tcp4Table(pid, holdTuple) })
		o.identify = func(pid uint32) (platform.Owner, error) {
			winclock.System.Wait(context.Background(), 30*time.Millisecond)
			return o.process(pid)
		}
		owner, err, took := timedLookup(o, context.Background(), holdTuple)
		if err != nil || owner.PID != pid || took < ownerLookupBound || o.Stats().TCPLateIdentities != 1 {
			t.Fatalf("late identity: %+v %v after %v late=%d", owner, err, took, o.Stats().TCPLateIdentities)
		}
	})
	t.Run("an identity step past the hold still ends unknown", func(t *testing.T) {
		o := NewOwners()
		slowTables(o, func() time.Duration { return 40 * time.Millisecond }, func() []byte { return tcp4Table(pid, holdTuple) })
		o.identify = func(pid uint32) (platform.Owner, error) {
			winclock.System.Wait(context.Background(), ownerOverloadHold)
			return o.process(pid)
		}
		if _, err, _ := timedLookup(o, context.Background(), holdTuple); !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("identity past the hold: %v", err)
		}
	})
	t.Run("the caller's context still cancels a hold", func(t *testing.T) {
		o := NewOwners()
		slowTables(o, func() time.Duration { return 200 * time.Millisecond }, func() []byte { return tcp4Table(pid, holdTuple) })
		ctx, cancel := context.WithCancel(context.Background())
		time.AfterFunc(80*time.Millisecond, cancel)
		_, err, took := timedLookup(o, ctx, holdTuple)
		if !errors.Is(err, context.Canceled) || took > 150*time.Millisecond {
			t.Fatalf("cancelled hold: %v after %v", err, took)
		}
	})
	if bound := NewOwners().TCPLookupBound(); bound != ownerOverloadHold {
		t.Fatalf("forwarder bound %v", bound)
	}
}
