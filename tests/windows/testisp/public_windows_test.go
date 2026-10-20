package main

import (
	"errors"
	"fmt"
	"io"
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
