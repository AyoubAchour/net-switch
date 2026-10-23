//go:build windows

package winengine

import (
	"context"
	"encoding/binary"
	"errors"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/AyoubAchour/net-switch/internal/engine/platform"
	"github.com/AyoubAchour/net-switch/internal/winclock"
	"golang.org/x/sys/windows"
)

// Synthetic native rows: these tests never open sockets or start the engine.
func udpHoldTable(keys []netip.AddrPort, pid uint32, created uint64) []byte {
	stride := 160
	if keys[0].Addr().Is6() {
		stride = 176
	}
	b := make([]byte, 8+stride*len(keys))
	binary.LittleEndian.PutUint32(b, uint32(len(keys)))
	for i, key := range keys {
		r := b[8+i*stride:]
		if key.Addr().Is4() {
			a := key.Addr().As4()
			copy(r, a[:])
			binary.BigEndian.PutUint16(r[4:], key.Port())
			binary.LittleEndian.PutUint32(r[8:], pid)
			binary.LittleEndian.PutUint64(r[16:], created+uint64(i))
		} else {
			a := key.Addr().As16()
			copy(r, a[:])
			binary.BigEndian.PutUint16(r[20:], key.Port())
			binary.LittleEndian.PutUint32(r[24:], pid)
			binary.LittleEndian.PutUint64(r[32:], created+uint64(i))
		}
	}
	return b
}

func TestUDPGenerationHoldSharesOneSlowRead(t *testing.T) {
	for _, address := range []string{"192.0.2.1", "2001:db8::1"} {
		t.Run(address, func(t *testing.T) {
			const count = 16
			o := NewOwners()
			keys := make([]netip.AddrPort, count)
			for i := range keys {
				keys[i] = netip.AddrPortFrom(netip.MustParseAddr(address), uint16(40000+i))
			}
			var arrived sync.WaitGroup
			arrived.Add(count)
			o.beforeUDPSnapshot = func() { arrived.Done(); arrived.Wait() }
			var reads atomic.Uint64
			o.readUDP = func(ctx context.Context, family uint32, _ *[]uint64) ([]byte, error) {
				reads.Add(1)
				readStart := winclock.Now()
				if (family == windows.AF_INET6) != keys[0].Addr().Is6() {
					return nil, errors.New("wrong table family")
				}
				// Wait until every caller crosses its actual 50 ms bound. No
				// fixed extra delay on a loaded ARM64 runner.
				for o.udpHolds.Load() != count || winclock.Since(readStart) <= ownerLookupBound {
					if err := winclock.System.Wait(ctx, time.Millisecond); err != nil {
						return nil, err
					}
				}
				return udpHoldTable(keys, 123, 1000), nil
			}
			o.identify = func(uint32) (platform.Owner, error) {
				t.Error("expired identity must not run after the slow snapshot")
				return platform.Owner{}, nil
			}
			var workers sync.WaitGroup
			for i, key := range keys {
				workers.Go(func() {
					start := winclock.Now()
					owner, err := o.UDP(t.Context(), key)
					took := winclock.Since(start)
					want := platform.Owner{Generation: (socketOwner{123, 1000 + uint64(i)}).generation()}
					if owner != want || !errors.Is(err, context.DeadlineExceeded) || took < ownerLookupBound || took >= ownerOverloadHold {
						t.Errorf("held source %s: %+v %v after %v; want %+v", key, owner, err, took, want)
					}
				})
			}
			workers.Wait()
			stats := o.Stats()
			if reads.Load() != 1 || stats.UDPRefreshes != 1 || stats.UDPHolds != count || stats.UDPHeldGenerations != count || stats.UDPIdentityExpiredGeneration != count || stats.UDPGenerationRefusals != 0 || stats.UDPReadMaxUS < uint64(ownerLookupBound.Microseconds()) {
				t.Fatalf("slow read was duplicated or generations lost: %+v; reads=%d", stats, reads.Load())
			}
			t.Logf("one shared native read; holds=%d generations=%d unknown=%d refusals=%d", stats.UDPHolds, stats.UDPHeldGenerations, stats.UDPIdentityExpiredGeneration, stats.UDPGenerationRefusals)
		})
	}
}

func TestUDPGenerationHoldTimeoutRecordsReason(t *testing.T) {
	o := NewOwners()
	key := netip.MustParseAddrPort("192.0.2.1:40000")
	release, finished := make(chan struct{}), make(chan struct{})
	defer func() { close(release); <-finished }()
	o.readUDP = func(context.Context, uint32, *[]uint64) ([]byte, error) {
		defer close(finished)
		<-release // emulate an uninterruptible native read beyond 250 ms
		return udpHoldTable([]netip.AddrPort{key}, 123, 1000), nil
	}
	start := winclock.Now()
	owner, err := o.UDP(t.Context(), key)
	took := winclock.Since(start)
	if owner != (platform.Owner{}) || !errors.Is(err, context.DeadlineExceeded) || took < ownerOverloadHold || took > ownerOverloadHold+100*time.Millisecond {
		t.Fatalf("overlong read: %+v %v after %v", owner, err, took)
	}
	stats := o.Stats()
	if stats.UDPGenerationRefusals != 1 || stats.UDPHeldGenerations != 0 || stats.UDPIdentityExpiredGeneration != 0 || len(stats.Failures) != 1 {
		t.Fatalf("timeout attribution: %+v", stats)
	}
	f := stats.Failures[0]
	if f.Kind != "udp-generation" || f.Stage != "GetExtendedUdpTable snapshot" || !f.Deadline || f.DurationUS < ownerOverloadHold.Microseconds() || f.Source != key || f.Generation != "" {
		t.Fatalf("missing refusal evidence: %+v", f)
	}
	t.Logf("generation refusal: reason=%s stage=%s durationUS=%d", f.Error, f.Stage, f.DurationUS)
}

func TestUDPGenerationIdentityOnlyExpiry(t *testing.T) {
	for _, late := range []bool{false, true} {
		o := NewOwners()
		key := netip.MustParseAddrPort("192.0.2.1:40000")
		o.readUDP = func(context.Context, uint32, *[]uint64) ([]byte, error) {
			return udpHoldTable([]netip.AddrPort{key}, 123, 1000), nil
		}
		known := platform.Owner{PID: 123, StartTime: 99, AppID: "app", Path: "app.exe"}
		o.identify = func(uint32) (platform.Owner, error) {
			if late {
				winclock.System.Wait(t.Context(), ownerLookupBound+time.Millisecond)
			}
			return known, nil
		}
		owner, err := o.UDP(t.Context(), key)
		known.Generation = (socketOwner{123, 1000}).generation()
		if late {
			if owner != (platform.Owner{Generation: known.Generation}) || !errors.Is(err, context.DeadlineExceeded) || o.Stats().UDPIdentityExpiredGeneration != 1 {
				t.Fatalf("late identity was accepted or lost its generation: %+v %v", owner, err)
			}
		} else if err != nil || owner != known {
			t.Fatalf("fast identity changed: %+v %v", owner, err)
		}
		if o.Stats().UDPGenerationRefusals != 0 {
			t.Fatal("identity-only expiry was counted as a generation refusal")
		}
	}
}

func TestUDPGenerationOuterCancellationDiscardsReadyRow(t *testing.T) {
	o := NewOwners()
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	key := netip.MustParseAddrPort("192.0.2.1:40000")
	o.readUDP = func(context.Context, uint32, *[]uint64) ([]byte, error) {
		return udpHoldTable([]netip.AddrPort{key}, 123, 1000), nil
	}
	o.identify = func(uint32) (platform.Owner, error) {
		cancel()
		return platform.Owner{PID: 123, AppID: "app"}, nil
	}
	owner, err := o.UDP(ctx, key)
	if owner != (platform.Owner{}) || !errors.Is(err, context.Canceled) || o.Stats().UDPGenerationRefusals != 1 {
		t.Fatalf("canceled setup admitted ready generation: %+v %v", owner, err)
	}
}

func TestUDPGenerationDistinguishesProcessesWithoutIdentity(t *testing.T) {
	if (socketOwner{123, 1000}).generation() == (socketOwner{124, 1000}).generation() {
		t.Fatal("equal timestamps in different processes share a generation")
	}
}

func TestUDPGenerationCancellationDoesNotPoisonSharedRead(t *testing.T) {
	o := NewOwners()
	key := netip.MustParseAddrPort("192.0.2.1:40000")
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	var arrived sync.WaitGroup
	arrived.Add(2)
	o.beforeUDPSnapshot = func() { arrived.Done(); arrived.Wait() }
	o.readUDP = func(readCtx context.Context, _ uint32, _ *[]uint64) ([]byte, error) {
		cancel()
		if err := winclock.System.Wait(readCtx, 60*time.Millisecond); err != nil {
			return nil, err
		}
		return udpHoldTable([]netip.AddrPort{key}, 123, 1000), nil
	}
	var workers sync.WaitGroup
	for _, canceled := range []bool{false, true} {
		workers.Go(func() {
			parent := t.Context()
			if canceled {
				parent = ctx
			}
			owner, err := o.UDP(parent, key)
			if canceled {
				if owner != (platform.Owner{}) || !errors.Is(err, context.Canceled) {
					t.Errorf("canceled waiter: %+v %v", owner, err)
				}
			} else if owner.Generation != (socketOwner{123, 1000}).generation() || !errors.Is(err, context.DeadlineExceeded) {
				t.Errorf("peer lost shared read: %+v %v", owner, err)
			}
		})
	}
	workers.Wait()
	if stats := o.Stats(); stats.UDPRefreshes != 1 || stats.UDPGenerationRefusals != 1 || stats.UDPIdentityExpiredGeneration != 1 {
		t.Fatalf("shared cancellation attribution: %+v", stats)
	}
}

func TestUDPGenerationHoldCannotReusePositiveSnapshot(t *testing.T) {
	o := NewOwners()
	key := netip.MustParseAddrPort("192.0.2.1:40000")
	old := &udpOwnerSnapshot{at: winclock.Now(), rows: newUDPRows(1, 0)}
	old.rows.add(key, socketOwner{123, 1000})
	o.udpSnapshots[0].Store(old)
	o.readUDP = func(context.Context, uint32, *[]uint64) ([]byte, error) {
		return udpHoldTable([]netip.AddrPort{key}, 123, 2000), nil
	}
	o.identify = func(uint32) (platform.Owner, error) { return platform.Owner{PID: 123, AppID: "app"}, nil }
	owner, err := o.UDP(t.Context(), key)
	if err != nil || owner.Generation != (socketOwner{123, 2000}).generation() || o.Stats().UDPRefreshes != 1 {
		t.Fatalf("new setup reused an earlier generation: %+v %v", owner, err)
	}
}
