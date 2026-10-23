package linux

import (
	"context"
	"errors"
	"fmt"
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
	return probe.Run(ctx, r, probe.Options{TLS: p.ProbeTLS, Unavailable: probeUnavailable,
		Dial: func(ctx context.Context, dst netip.AddrPort) (net.Conn, error) {
			if view := p.bindings.Load(); view == nil || !view.capturing {
				return nil, probe.ErrUnavailable
			}
			if p.ProbeError != nil {
				if err := p.ProbeError(); err != nil {
					return nil, p.classifyProbeError(line, dst, err)
				}
			}
			c, err := p.DialTCP(ctx, line, dst)
			return c, p.classifyProbeError(line, dst, err)
		}})
}

var errProbePorts = errors.New("probe local port exhaustion")

func (p *Platform) classifyProbeError(line string, dst netip.AddrPort, err error) error {
	if errors.Is(err, syscall.EADDRNOTAVAIL) {
		binding, bindingErr := p.binding(line, dst.Addr().Is6())
		if bindingErr != nil {
			return fmt.Errorf("probe route unavailable: %v: %w", bindingErr, err)
		}
		if !probeHasSource(binding, dst.Addr()) {
			return fmt.Errorf("probe line %q has no usable source for %s: %w", line, dst.Addr(), err)
		}
		return fmt.Errorf("%w: %w", errProbePorts, err)
	}
	return err
}

func probeHasSource(line lineState, target netip.Addr) bool {
	for _, source := range line.Addresses {
		if source.Is4() == target.Is4() && source.IsGlobalUnicast() {
			return true // tentative/failed-DAD addresses never enter the binding
		}
	}
	return false
}

func probeUnavailable(err error) bool {
	for _, errno := range []error{syscall.EMFILE, syscall.ENFILE, syscall.ENOBUFS, syscall.ENOMEM, syscall.EADDRINUSE, errProbePorts} {
		if errors.Is(err, errno) {
			return true
		}
	}
	return false
}
