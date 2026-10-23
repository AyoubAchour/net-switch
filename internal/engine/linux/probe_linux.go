package linux

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"syscall"

	"github.com/AyoubAchour/net-switch/internal/engine/platform"
	"github.com/AyoubAchour/net-switch/internal/engine/probe"
)

func (p *Platform) Probe(ctx context.Context, line, operator string) (platform.ProbeResult, error) {
	return p.ProbeConfigured(ctx, line, platform.ProbeRequest{Operator: operator})
}

func (p *Platform) ProbeConfigured(ctx context.Context, line string, r platform.ProbeRequest) (platform.ProbeResult, error) {
	if view := p.bindings.Load(); view == nil || !view.capturing {
		return platform.ProbeResult{Outcome: "engineUnavailable", Error: "routing engine is not running"}, nil
	}
	return probe.Run(ctx, r, probe.Options{TLS: p.ProbeTLS, Unavailable: probeUnavailable,
		Dial: func(ctx context.Context, dst netip.AddrPort) (net.Conn, error) {
			if p.ProbeError != nil {
				if err := p.ProbeError(); err != nil {
					return nil, err
				}
			}
			return p.DialTCP(ctx, line, dst)
		}})
}

func probeUnavailable(err error) bool {
	for _, errno := range []error{syscall.EMFILE, syscall.ENFILE, syscall.ENOBUFS, syscall.ENOMEM, syscall.EADDRINUSE, syscall.EADDRNOTAVAIL} {
		if errors.Is(err, errno) {
			return true
		}
	}
	return false
}
