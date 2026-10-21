package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"syscall"
)

func publicProbeFailure(endpoint, phase string, status int, verified bool, cause error) error {
	label := "public HTTPS failure (origin unproven)"
	switch {
	case verified && status >= 500 && status < 600:
		label = "public target unavailable"
	case errors.Is(cause, syscall.Errno(10054)):
		label = "transport reset (origin unproven)"
	case errors.Is(cause, io.EOF), errors.Is(cause, io.ErrUnexpectedEOF):
		label = "early close (origin unproven)"
	}
	return fmt.Errorf("%s: endpoint=%s; phase=%s; HTTP=%d; TLS verified=%t: %w", label, endpoint, phase, status, verified, cause)
}

// The harness matches this line to tell a connect-time refusal (such as an
// unreachable network) from a later timeout or TLS failure.
func localProbeFailure(endpoint, phase string, errno syscall.Errno, cause error) error {
	return fmt.Errorf("local TLS failure: endpoint=%s; phase=%s; winsock=%d: %w", endpoint, phase, uint(errno), cause)
}

// connectTracker records how far the probe's TCP connect got. The HTTP client
// can report only its own deadline, which hides whether the connect finished.
type connectTracker struct {
	mu        sync.Mutex
	attempted bool
	connected bool
	err       error
}

func (c *connectTracker) dial(dial func(context.Context, string, string) (net.Conn, error)) func(context.Context, string, string) (net.Conn, error) {
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		c.mu.Lock()
		c.attempted = true
		c.mu.Unlock()
		conn, err := dial(ctx, network, address)
		c.mu.Lock()
		defer c.mu.Unlock()
		if err != nil {
			c.err = err
		} else {
			c.connected = true
		}
		return conn, err
	}
}

// phase is "connect" while a started connect has not finished, with the
// Winsock error if the connect itself returned one, and otherwise "request".
func (c *connectTracker) phase() (string, syscall.Errno) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.attempted || c.connected {
		return "request", 0
	}
	var errno syscall.Errno
	errors.As(c.err, &errno)
	return "connect", errno
}
