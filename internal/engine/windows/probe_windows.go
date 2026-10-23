package winengine

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"time"

	"github.com/AyoubAchour/net-switch/internal/engine/platform"
	"github.com/AyoubAchour/net-switch/internal/engine/probe"
	"github.com/AyoubAchour/net-switch/internal/winclock"
	"golang.org/x/sys/windows"
)

func (d *Dialer) Probe(ctx context.Context, line, operator string) (platform.ProbeResult, error) {
	return d.ProbeConfigured(ctx, line, platform.ProbeRequest{Operator: operator})
}

func (d *Dialer) ProbeConfigured(ctx context.Context, line string, r platform.ProbeRequest) (platform.ProbeResult, error) {
	if !d.Routes.active.Load() {
		return platform.ProbeResult{Outcome: "engineUnavailable", Error: "routing engine is not running"}, nil
	}
	started := winclock.Now()
	return probe.Run(ctx, r, probe.Options{TLS: d.ProbeTLS, Elapsed: func() time.Duration { return winclock.Since(started) }, Unavailable: probeUnavailable,
		Dial: func(ctx context.Context, dst netip.AddrPort) (net.Conn, error) {
			if d.ProbeError != nil {
				if err := d.ProbeError(); err != nil {
					return nil, err
				}
			}
			return d.dialProbe(ctx, line, dst)
		}})
}

func probeUnavailable(err error) bool {
	return portLimit(err) || errors.Is(err, windows.WSAEMFILE) || errors.Is(err, windows.ERROR_NOT_ENOUGH_MEMORY) || errors.Is(err, windows.ERROR_OUTOFMEMORY)
}

func (d *Dialer) DialTestTCP(ctx context.Context, line string, dst netip.AddrPort) (net.Conn, error) {
	return d.dialProbe(ctx, line, dst)
}
