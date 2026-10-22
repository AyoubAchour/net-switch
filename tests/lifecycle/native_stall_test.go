package lifecycle_test

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"runtime"
	"syscall"
	"testing"
	"time"
)

type nativeRecoveryTimer struct {
	start time.Time
	clock time.Duration
}

func newNativeRecoveryTimer() nativeRecoveryTimer {
	return nativeRecoveryTimer{start: time.Now(), clock: nativeMeasurementNow()}
}

func (r nativeRecoveryTimer) elapsed() time.Duration { return nativeMeasurementNow() - r.clock }

func nativeFreshFlow(t *testing.T, fixture tunFixture, ctx context.Context, phase string, recovery nativeRecoveryTimer, bound time.Duration) {
	t.Helper()
	passed := false
	freshAfter := time.Duration(-1)
	defer func() {
		if freshAfter < 0 {
			freshAfter = recovery.elapsed()
		}
		t.Logf("M4_RECOVERY phase=%s fresh_flow=%t fresh_after=%s bound=%s single_attempt=true", phase, passed, freshAfter, bound)
	}()
	deadline := recovery.start.Add(bound)
	dialDeadline := time.Now().Add(5 * time.Second)
	if deadline.Before(dialDeadline) {
		dialDeadline = deadline
	}
	ctx, cancel := context.WithDeadline(ctx, dialDeadline)
	defer cancel()
	conn, err := fixture.dial(ctx, "tcp4", fixture.target)
	if err != nil {
		t.Fatal("fresh flow recovery", phase, err)
	}
	defer conn.Close()
	echoDeadline := time.Now().Add(5 * time.Second)
	if deadline.Before(echoDeadline) {
		echoDeadline = deadline
	}
	nativeEchoDeadline(t, conn, "fresh-after-"+phase, echoDeadline)
	freshAfter = recovery.elapsed()
	if freshAfter > bound {
		t.Fatal("fresh-flow recovery exceeded its bound", phase, freshAfter, bound)
	}
	passed = true
}

func stallReadKind(n int, err error) string {
	if n != 0 {
		return "delivered"
	}
	if errors.Is(err, os.ErrDeadlineExceeded) {
		return "poll-deadline"
	}
	if err != nil {
		return "terminal"
	}
	return "empty-read"
}

type nativeSocketObservation struct {
	sample       func(string)
	verifyGiveUp func(error) error
}

func stallReadDisposition(n int, err error, verifyGiveUp func(error) error) (string, error) {
	kind := stallReadKind(n, err)
	if kind == "poll-deadline" {
		return kind, nil
	}
	if kind == "terminal" && verifyGiveUp != nil {
		if proof := verifyGiveUp(err); proof == nil {
			return "os-give-up", nil
		} else {
			return kind, fmt.Errorf("unproved OS give-up: %w", proof)
		}
	}
	return kind, fmt.Errorf("unexpected stalled read: kind=%s bytes=%d error=%v", kind, n, err)
}

// A local OS retransmission timeout is an observation only after independent
// socket evidence proves it. Delivery, reset, EOF and other errors still fail.
// A quiet-stream control supplies no give-up verifier and remains strict.
type stalledTraffic struct {
	conn         net.Conn
	sent         time.Time
	polls        int
	fate         string
	sample       func(string)
	verifyGiveUp func(error) error
	giveUpAfter  time.Duration
}

func (s *stalledTraffic) poll(t *testing.T) {
	t.Helper()
	if s.fate != "" {
		time.Sleep(time.Second)
		return
	}
	deadline := time.Now().Add(time.Second)
	if err := s.conn.SetReadDeadline(deadline); err != nil {
		t.Fatal(err)
	}
	var b [1]byte
	n, err := s.conn.Read(b[:])
	kind, failure := stallReadDisposition(n, err, s.verifyGiveUp)
	if kind == "poll-deadline" {
		s.polls++
		return
	}
	s.fate = kind
	if kind == "os-give-up" {
		s.giveUpAfter = time.Since(s.sent)
	}
	var errno syscall.Errno
	_ = errors.As(err, &errno)
	t.Logf("M4_FLOW event=%s platform=%s/%s since_send=%s poll_deadlines=%d bytes=%d errno=%d read_deadline=%s error_type=%T error=%v", kind, runtime.GOOS, runtime.GOARCH, time.Since(s.sent), s.polls, n, errno, deadline.UTC().Format(time.RFC3339Nano), err, err)
	s.sample("first-flow-event")
	if failure != nil {
		t.Error(failure)
	}
}

func (s *stalledTraffic) giveUpTime() string {
	if s.fate == "os-give-up" {
		return s.giveUpAfter.String()
	}
	return "not-observed"
}

func (s *stalledTraffic) outcome() string {
	if s.fate != "" {
		return s.fate
	}
	return "no-delivery-no-terminal-error"
}

func TestNativeStallAcceptsOnlyProvedOSGiveUp(t *testing.T) {
	proved := func(error) error { return nil }
	for _, tc := range []struct {
		name   string
		n      int
		err    error
		verify func(error) error
		want   string
		failed bool
	}{
		{"polling remains temporary", 0, os.ErrDeadlineExceeded, nil, "poll-deadline", false},
		{"explicit proof required", 0, syscall.ETIMEDOUT, nil, "terminal", true},
		{"verified OS expiry", 0, syscall.ETIMEDOUT, proved, "os-give-up", false},
		{"failed proof", 0, syscall.ETIMEDOUT, func(error) error { return errors.New("no retransmissions") }, "terminal", true},
		{"data always fails", 1, syscall.ETIMEDOUT, proved, "delivered", true},
		{"empty success always fails", 0, nil, proved, "empty-read", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			kind, err := stallReadDisposition(tc.n, tc.err, tc.verify)
			if kind != tc.want || (err != nil) != tc.failed {
				t.Fatal(kind, err)
			}
		})
	}
}

func TestNativeStallReadClassification(t *testing.T) {
	for _, tc := range []struct {
		name string
		n    int
		err  error
		want string
	}{
		{"Go read deadline", 0, &net.OpError{Op: "read", Err: os.ErrDeadlineExceeded}, "poll-deadline"},
		{"Winsock terminal timeout", 0, &net.OpError{Op: "read", Err: os.NewSyscallError("wsarecv", syscall.Errno(10060))}, "terminal"},
		{"OS timeout on Unix", 0, &net.OpError{Op: "read", Err: syscall.ETIMEDOUT}, "terminal"},
		{"peer close", 0, io.EOF, "terminal"},
		{"reset", 0, syscall.ECONNRESET, "terminal"},
		{"data with deadline", 1, os.ErrDeadlineExceeded, "delivered"},
		{"empty success", 0, nil, "empty-read"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := stallReadKind(tc.n, tc.err); got != tc.want {
				t.Fatal(got, tc.want)
			}
		})
	}
}
