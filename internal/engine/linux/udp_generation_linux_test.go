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
			if stats.UDPIdentityExpiredGeneration != 1 || stats.Timeout != 1 || len(stats.UDPGenerationFailures) != 0 {
				t.Fatalf("recovered cookie must be a distinct timeout, not a generation failure: %+v", stats)
			}
			t.Logf("identity expired before query; one exact request returned SO_COOKIE=%s, unknown owner, recovery count=1", cookie)
		})
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
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	_, rebound, newCookie := generationSocket(t, int(tuple.Source.Port()))
	if rebound != tuple || newCookie == oldCookie {
		t.Fatalf("fixture did not replace the socket at the same tuple: old=%s new=%s tuple=%+v", oldCookie, newCookie, rebound)
	}
	o.afterUDPIdentityContext = func(identity context.Context) { <-identity.Done() }
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
