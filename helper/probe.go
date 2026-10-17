package main

import (
	"context"
	"fmt"
	"math/bits"
	"net"
	"net/netip"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/windows"
)

type probeResult struct {
	OK     bool   `json:"ok"`
	MS     int64  `json:"ms,omitempty"`
	Target string `json:"target,omitempty"`
	Error  string `json:"error,omitempty"`
}

const ipUnicastIf = 31

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

func probe(opts options) probeResult {
	targets, err := probeTargets(opts.targets)
	if err != nil {
		return probeResult{Error: err.Error()}
	}
	adapter, err := net.InterfaceByIndex(int(opts.index))
	if err != nil {
		return probeResult{Error: err.Error()}
	}
	addresses, err := adapter.Addrs()
	if err != nil {
		return probeResult{Error: err.Error()}
	}
	var local net.IP
	for _, address := range addresses {
		ip, _, err := net.ParseCIDR(address.String())
		if err == nil && ip.To4() != nil && !ip.IsLinkLocalUnicast() && !ip.IsLoopback() {
			local = ip.To4()
			break
		}
	}
	if local == nil {
		return probeResult{Error: "interface has no usable IPv4 address"}
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(opts.timeout)*time.Millisecond)
	defer cancel()
	return raceProbes(ctx, targets, func(ctx context.Context, target string) error {
		dialer := net.Dialer{
			LocalAddr: &net.TCPAddr{IP: local},
			Control: func(_, _ string, raw syscall.RawConn) error {
				var socketErr error
				err := raw.Control(func(fd uintptr) {
					// Windows expects the interface index in network byte order.
					socketErr = windows.SetsockoptInt(windows.Handle(fd), windows.IPPROTO_IP, ipUnicastIf, int(bits.ReverseBytes32(uint32(opts.index))))
				})
				if err != nil {
					return err
				}
				return socketErr
			},
		}
		connection, err := dialer.DialContext(ctx, "tcp4", target)
		if err == nil {
			connection.Close()
		}
		return err
	})
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
