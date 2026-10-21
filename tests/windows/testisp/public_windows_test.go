package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"syscall"
	"testing"
)

func TestPublicProbeFailureEvidence(t *testing.T) {
	for _, verified := range []bool{false, true} {
		for _, status := range []int{0, 200, 404, 499, 500, 503, 599, 600} {
			err := publicProbeFailure("https://1.1.1.1/cdn-cgi/trace", "body", status, verified, errors.New("bad response"))
			if got := strings.HasPrefix(err.Error(), "public target unavailable"); got != (verified && status >= 500 && status < 600) {
				t.Fatal(err)
			}
		}
	}
	for _, tc := range []struct {
		cause error
		label string
	}{
		{syscall.Errno(10054), "transport reset (origin unproven)"},
		{io.EOF, "early close (origin unproven)"},
		{io.ErrUnexpectedEOF, "early close (origin unproven)"},
	} {
		err := publicProbeFailure("https://1.1.1.1/cdn-cgi/trace", "request", 0, false, fmt.Errorf("wrapped: %w", tc.cause))
		if !strings.HasPrefix(err.Error(), tc.label) || !errors.Is(err, tc.cause) {
			t.Fatal(err)
		}
	}
}

func TestConnectTrackerPhase(t *testing.T) {
	unreachable := &net.OpError{Op: "dial", Net: "tcp", Err: os.NewSyscallError("connectex", syscall.Errno(10051))}
	for _, tc := range []struct {
		name  string
		err   error
		phase string
		errno syscall.Errno
	}{
		{"connected", nil, "request", 0},
		{"unreachable", unreachable, "connect", 10051},
		{"deadline", context.DeadlineExceeded, "connect", 0},
	} {
		var c connectTracker
		if phase, _ := c.phase(); phase != "request" {
			t.Fatalf("%s: no connect yet reported %s", tc.name, phase)
		}
		dial := c.dial(func(context.Context, string, string) (net.Conn, error) {
			if phase, errno := c.phase(); phase != "connect" || errno != 0 {
				t.Fatalf("%s: unfinished connect reported %s/%d", tc.name, phase, errno)
			}
			if tc.err != nil {
				return nil, tc.err
			}
			client, server := net.Pipe()
			server.Close()
			return client, nil
		})
		conn, err := dial(context.Background(), "tcp", "203.0.113.44:443")
		if conn != nil {
			conn.Close()
		}
		if !errors.Is(err, tc.err) {
			t.Fatalf("%s: dial error %v", tc.name, err)
		}
		if phase, errno := c.phase(); phase != tc.phase || errno != tc.errno {
			t.Fatalf("%s: got %s/%d, want %s/%d", tc.name, phase, errno, tc.phase, tc.errno)
		}
	}
	err := localProbeFailure("https://203.0.113.44/", "connect", 10051, fmt.Errorf("wrapped: %w", unreachable))
	if !strings.HasPrefix(err.Error(), "local TLS failure: endpoint=https://203.0.113.44/; phase=connect; winsock=10051: ") || !errors.Is(err, syscall.Errno(10051)) {
		t.Fatal(err)
	}
}
