//go:build linux

package linux

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/AyoubAchour/net-switch/internal/engine/platform"
	"golang.org/x/sys/unix"
)

func generationSocket(t *testing.T, port int) (*net.UDPConn, platform.Tuple, string) {
	t.Helper()
	c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: port})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	raw, err := c.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var cookie uint64
	var socketErr error
	if err := raw.Control(func(fd uintptr) {
		cookie, socketErr = unix.GetsockoptUint64(int(fd), unix.SOL_SOCKET, unix.SO_COOKIE)
	}); err != nil || socketErr != nil || cookie == 0 {
		t.Fatalf("independent SO_COOKIE: %x %v %v", cookie, err, socketErr)
	}
	tuple := platform.Tuple{
		Source:      netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(c.LocalAddr().(*net.UDPAddr).Port)),
		Destination: netip.MustParseAddrPort("192.0.2.1:443"),
	}
	return c, tuple, strconv.FormatUint(cookie, 16)
}

func TestUDPGenerationSurvivesIdentityExpiryBeforeQuery(t *testing.T) {
	for _, state := range []string{"cold", "cached-owner-and-pooled-query"} {
		t.Run(state, func(t *testing.T) {
			_, tuple, cookie := generationSocket(t, 0)
			o := newTestOwners(t)
			// Leave headroom for CI instrumentation; production NAT supplies 50 ms.
			outer, cancel := context.WithTimeout(t.Context(), time.Second)
			defer cancel()
			if state != "cold" {
				rows, err := o.query(outer, unix.AF_INET, unix.IPPROTO_UDP, tuple.Source, tuple.Destination)
				if err != nil || len(rows) != 1 {
					t.Fatalf("warm exact query: %+v %v", rows, err)
				}
				owner, err := o.holders(outer, rows[0])
				if err != nil || owner.PID != uint32(os.Getpid()) || owner.AppID == "" || owner.Generation != cookie || len(o.queries.idle) != 1 {
					t.Fatalf("fixture must cache a real owner and pool a query socket: %+v %v idle=%d", owner, err, len(o.queries.idle))
				}
			}
			o.afterUDPIdentityContext = func(identity context.Context) {
				<-identity.Done()
				if !errors.Is(identity.Err(), context.DeadlineExceeded) || outer.Err() != nil {
					t.Fatalf("fixture did not expire only identity: child=%v outer=%v", identity.Err(), outer.Err())
				}
				// Reproduce the old coupling at the real query boundary. It must
				// fail before sending, even though the held socket has a cookie.
				_, err := o.query(identity, unix.AF_INET, unix.IPPROTO_UDP, tuple.Source, tuple.Destination)
				var failure *diagQueryError
				if !errors.As(err, &failure) || !errors.Is(err, context.DeadlineExceeded) || failure.Trace.Stage != "context" || failure.Trace.SentNS != 0 {
					t.Fatalf("old deadline oracle did not reproduce the unsent query: %v", err)
				}
			}
			before := diagSequence.Load()
			owner, err := o.UDPFor(outer, tuple)
			if !errors.Is(err, context.DeadlineExceeded) || owner != (platform.Owner{Generation: cookie}) || outer.Err() != nil {
				t.Fatalf("expired identity must retain only the real socket cookie: %+v %v outer=%v", owner, err, outer.Err())
			}
			if requests := diagSequence.Load() - before; requests != 1 {
				t.Fatalf("cookie recovery sent %d queries, want exactly one", requests)
			}
			stats := o.Stats().(lookupStats)
			if stats.UDPIdentityExpiredGeneration != 1 || stats.UDPGenerationQueryAfterIdentityDeadline != 1 || stats.UDPLateIdentityDiscarded != 0 || stats.Timeout != 1 || len(stats.UDPGenerationFailures) != 0 {
				t.Fatalf("recovered cookie must be a distinct timeout, not a generation failure: %+v", stats)
			}
			snapshot, err := o.Snapshot(outer, []netip.AddrPort{tuple.Source})
			if err != nil || snapshot[tuple.Source] != owner {
				t.Fatalf("reconciliation changed the recovered unknown identity: %+v %v", snapshot, err)
			}
			t.Logf("identity expired before query; one exact request returned SO_COOKIE=%s, unknown owner, recovery count=1", cookie)
		})
	}
}

func TestUDPIdentityExpiryAfterResolutionKeepsReconciliationUnknown(t *testing.T) {
	app, knownTuple, cookie := generationSocket(t, 0)
	o := newTestOwners(t)
	outer, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	rows, err := o.query(outer, unix.AF_INET, unix.IPPROTO_UDP, knownTuple.Source, knownTuple.Destination)
	if err != nil || len(rows) != 1 || rows[0].generation() != cookie {
		t.Fatalf("real socket query: %+v %v", rows, err)
	}
	known, err := o.holders(outer, rows[0])
	if err != nil || known.PID != uint32(os.Getpid()) || known.AppID == "" {
		t.Fatalf("fixture must warm a real known holder: %+v %v", known, err)
	}
	// One wildcard socket can back different local source addresses. Losing
	// its holder cache globally would close this already-known sibling too.
	unknownTuple := knownTuple
	unknownTuple.Source = netip.AddrPortFrom(netip.MustParseAddr("127.0.0.2"), knownTuple.Source.Port())
	var paused bool
	o.afterUDPOwnerResolution = func(identity context.Context, result platform.Owner) {
		if result != known || lookupContextError(identity) != nil || len(o.cachedHolders(rows[0].cookie)) == 0 {
			t.Fatalf("fixture must resolve and cache identity before expiry: %+v child=%v", result, lookupContextError(identity))
		}
		// This is exactly the pre-fix disagreement: SnapshotAt already sees
		// a known holder, but the final lookup deadline will discard identity.
		before, err := o.Snapshot(outer, []netip.AddrPort{knownTuple.Source, unknownTuple.Source})
		if err != nil || before[unknownTuple.Source] != known {
			t.Fatalf("fixture lacks the pre-fix positive snapshot: %+v %v", before, err)
		}
		<-identity.Done()
		paused = true
	}
	unknown, err := o.UDPFor(outer, unknownTuple)
	if !paused || !errors.Is(err, context.DeadlineExceeded) || unknown != (platform.Owner{Generation: cookie}) || outer.Err() != nil {
		t.Fatalf("late identity was not discarded under a live setup context: %+v %v", unknown, err)
	}
	o.afterUDPOwnerResolution = nil
	snapshot, err := o.Snapshot(outer, []netip.AddrPort{knownTuple.Source, unknownTuple.Source})
	if err != nil || snapshot[unknownTuple.Source] != unknown || snapshot[knownTuple.Source] != known {
		t.Fatalf("reconciliation would close a live session: unknown=%+v known=%+v snapshot=%+v err=%v", unknown, known, snapshot, err)
	}
	stats := o.Stats().(lookupStats)
	if stats.Timeout != 1 || stats.HolderTimeouts != 0 || stats.ExpiredBeforeHolderScan != 0 || stats.UDPIdentityExpiredGeneration != 1 || stats.UDPGenerationQueryAfterIdentityDeadline != 0 || stats.UDPLateIdentityDiscarded != 1 {
		t.Fatalf("late publication was confused with a late query or holder timeout: %+v", stats)
	}
	if err := app.Close(); err != nil {
		t.Fatal(err)
	}
	snapshot, err = o.Snapshot(outer, []netip.AddrPort{knownTuple.Source, unknownTuple.Source})
	if err != nil || len(snapshot) != 0 || o.udpWasUnknown(unknownTuple.Source, rows[0].cookie) {
		t.Fatalf("unknown admission hid socket destruction or retained dead state: %+v %v", snapshot, err)
	}
	t.Log("real cached identity expired before publication; reconciliation retained both known and unknown siblings, then detected socket closure")
}

func TestUDPUnknownAdmissionPrunesOnlyUnreferencedResults(t *testing.T) {
	o := newTestOwners(t)
	first := netip.MustParseAddrPort("127.0.0.1:40000")
	second := netip.MustParseAddrPort("127.0.0.2:40000")
	const cookie = 123
	o.recordUDPUnknown(first, cookie, true)
	cutoff := time.Now()
	o.recordUDPUnknown(second, cookie, true)
	if !o.udpWasUnknown(first, cookie) || !o.udpWasUnknown(second, cookie) {
		t.Fatal("fixture must begin with both unknown records")
	}
	live := map[uint64]bool{cookie: true}
	referenced := map[netip.AddrPort]bool{first: true}
	o.pruneCookies(live, referenced, cutoff)
	if !o.udpWasUnknown(second, cookie) {
		t.Fatal("snapshot dropped a lookup completed after enumeration")
	}
	o.pruneCookies(live, referenced, time.Now().Add(time.Second))
	if !o.udpWasUnknown(first, cookie) || o.udpWasUnknown(second, cookie) {
		t.Fatal("pruning must retain the referenced source, not an unreferenced alias of its cookie")
	}
	if o.udpWasUnknown(first, cookie+1) {
		t.Fatal("a rebound socket inherited the old unknown decision")
	}
	o.recordUDPUnknown(first, cookie, false)
	if o.udpWasUnknown(first, cookie) {
		t.Fatal("a new known setup inherited the previous unknown decision")
	}
}

func TestUDPGenerationOuterCancellationRefuses(t *testing.T) {
	_, tuple, _ := generationSocket(t, 0)
	o := newTestOwners(t)
	outer, cancel := context.WithCancel(t.Context())
	defer cancel()
	o.afterUDPIdentityContext = func(identity context.Context) {
		<-identity.Done()
		cancel()
	}
	before := diagSequence.Load()
	owner, err := o.UDPFor(outer, tuple)
	if !errors.Is(err, context.Canceled) || owner != (platform.Owner{}) || diagSequence.Load() != before {
		t.Fatalf("outer cancellation must refuse without sending: %+v %v", owner, err)
	}
	stats := o.Stats().(lookupStats)
	if stats.UDPIdentityExpiredGeneration != 0 || len(stats.UDPGenerationFailures) != 1 || stats.UDPGenerationFailures[0].Query == nil || stats.UDPGenerationFailures[0].Query.SentNS != 0 {
		t.Fatalf("cancellation was counted as cookie recovery: %+v", stats)
	}
}

func TestUDPGenerationOuterCancellationWithQueuedReply(t *testing.T) {
	_, tuple, cookie := generationSocket(t, 0)
	o := newTestOwners(t)
	outer, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	rows, err := o.query(outer, unix.AF_INET, unix.IPPROTO_UDP, tuple.Source, tuple.Destination)
	if err != nil || len(rows) != 1 || rows[0].generation() != cookie || len(o.queries.idle) != 1 {
		t.Fatalf("fixture must first pool a real query: %+v %v", rows, err)
	}
	pooled := o.queries.idle[0].file
	ctx := &cancelBeforeReadContext{Context: outer, cancel: cancel, beforeCancel: func() {
		trace := diagQueryTrace{Sequence: diagSequence.Load()}
		trace.peek(pooled)
		if !trace.ReplyReady || !trace.ReplyFromKernel || !trace.ReplySequenceMatches || trace.ReplyCookie != cookie {
			t.Fatalf("cancellation did not occur with this socket's real reply queued: %+v", trace)
		}
	}}
	owner, err := o.UDPFor(ctx, tuple)
	if !errors.Is(err, context.Canceled) || owner != (platform.Owner{}) {
		t.Fatalf("outer cancellation admitted a queued cookie: %+v %v", owner, err)
	}
	stats := o.Stats().(lookupStats)
	if stats.UDPIdentityExpiredGeneration != 0 || len(stats.UDPGenerationFailures) != 1 || stats.UDPGenerationFailures[0].Query == nil || stats.UDPGenerationFailures[0].Query.SentNS == 0 {
		t.Fatalf("queued-reply cancellation lost its evidence: %+v", stats)
	}
}

func TestUDPGenerationCloseRebindAfterIdentityExpiry(t *testing.T) {
	first, tuple, oldCookie := generationSocket(t, 0)
	o := newTestOwners(t)
	outer, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	rows, err := o.query(outer, unix.AF_INET, unix.IPPROTO_UDP, tuple.Source, tuple.Destination)
	if err != nil || len(rows) != 1 || rows[0].generation() != oldCookie {
		t.Fatalf("original cookie must first be queried: %+v %v", rows, err)
	}
	o.afterUDPIdentityContext = func(identity context.Context) { <-identity.Done() }
	previous, err := o.UDPFor(outer, tuple)
	if !errors.Is(err, context.DeadlineExceeded) || previous != (platform.Owner{Generation: oldCookie}) || !o.udpWasUnknown(tuple.Source, rows[0].cookie) {
		t.Fatalf("fixture must first record a live unknown admission: %+v %v", previous, err)
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	_, rebound, newCookie := generationSocket(t, int(tuple.Source.Port()))
	if rebound != tuple || newCookie == oldCookie {
		t.Fatalf("fixture did not replace the socket at the same tuple: old=%s new=%s tuple=%+v", oldCookie, newCookie, rebound)
	}
	snapshot, err := o.Snapshot(outer, []netip.AddrPort{tuple.Source})
	if err != nil || snapshot[tuple.Source].Generation != newCookie || snapshot[tuple.Source].Generation == previous.Generation {
		t.Fatalf("unknown admission hid a real close/rebind: %+v %v", snapshot, err)
	}
	owner, err := o.UDPFor(outer, tuple)
	if !errors.Is(err, context.DeadlineExceeded) || owner != (platform.Owner{Generation: newCookie}) {
		t.Fatalf("rebound socket inherited stale generation: %+v %v; old=%s new=%s", owner, err, oldCookie, newCookie)
	}
}

func TestUDPGenerationKnownAmbiguousPortCannotUseLateExactCookie(t *testing.T) {
	_, tuple, _ := generationSocket(t, 0)
	o := newTestOwners(t)
	// A remembered ambiguity still requires the complete dump, even if an
	// exact query can find one socket. The cache is a restriction, not proof.
	o.ambiguousPorts[tuple.Source.Port()] = time.Now().Add(time.Second)
	o.afterUDPIdentityContext = func(identity context.Context) { <-identity.Done() }
	outer, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	owner, err := o.UDPFor(outer, tuple)
	if !errors.Is(err, context.DeadlineExceeded) || owner != (platform.Owner{}) {
		t.Fatalf("late exact cookie bypassed the ambiguity guard: %+v %v", owner, err)
	}
}
