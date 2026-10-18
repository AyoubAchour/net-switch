package main

import (
	"context"
	"fmt"
	"net/netip"
	"strings"
	"time"
)

type probeResult struct {
	OK     bool   `json:"ok"`
	MS     int64  `json:"ms,omitempty"`
	Target string `json:"target,omitempty"`
	Error  string `json:"error,omitempty"`
}

func probeTargets(value string) ([]string, error) {
	targets := strings.Split(value, ",")
	if len(targets) > 16 {
		return nil, fmt.Errorf("at most 16 probe targets are allowed")
	}
	for _, target := range targets {
		address, err := netip.ParseAddrPort(target)
		if err != nil || !address.Addr().Is4() || address.Port() == 0 {
			return nil, fmt.Errorf("invalid IPv4 probe target %q", target)
		}
	}
	return targets, nil
}

func raceProbes(ctx context.Context, targets []string, dial func(context.Context, string) error) probeResult {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	results := make(chan probeResult, len(targets))
	for _, target := range targets {
		go func() {
			start := time.Now()
			if err := dial(ctx, target); err != nil {
				results <- probeResult{Error: target + ": " + err.Error()}
			} else {
				results <- probeResult{OK: true, MS: max(1, time.Since(start).Milliseconds()), Target: target}
			}
		}()
	}
	failures := []string{}
	for range targets {
		select {
		case result := <-results:
			if result.OK {
				return result
			}
			failures = append(failures, result.Error)
		case <-ctx.Done():
			return probeResult{Error: ctx.Err().Error()}
		}
	}
	return probeResult{Error: strings.Join(failures, "; ")}
}
