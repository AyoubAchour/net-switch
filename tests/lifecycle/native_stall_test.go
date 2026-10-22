package lifecycle_test

import (
	"errors"
	"io"
	"net"
	"os"
	"syscall"
	"testing"
	"time"
)

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

// A terminal socket error is a failed held-flow assertion, never another poll
// deadline. Keep observing the service until the full fault window ends so a
// failure cannot hide its counters, cleanup or post-fault traffic outcomes.
type stalledTraffic struct {
	conn   net.Conn
	sent   time.Time
	polls  int
	fate   string
	sample func(string)
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
	kind := stallReadKind(n, err)
	if kind == "poll-deadline" {
		s.polls++
		return
	}
	s.fate = kind
	var errno syscall.Errno
	_ = errors.As(err, &errno)
	t.Logf("M4_FLOW first_failure=%s since_send=%s poll_deadlines=%d bytes=%d errno=%d read_deadline=%s error_type=%T error=%v", kind, time.Since(s.sent), s.polls, n, errno, deadline.UTC().Format(time.RFC3339Nano), err, err)
	s.sample("first-flow-failure")
	t.Errorf("held flow failed during stall: kind=%s bytes=%d error=%v", kind, n, err)
}

func (s *stalledTraffic) outcome() string {
	if s.fate != "" {
		return s.fate
	}
	return "no-delivery-no-terminal-error"
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
