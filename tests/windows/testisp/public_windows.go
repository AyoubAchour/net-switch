package main

import (
	"errors"
	"fmt"
	"io"
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
