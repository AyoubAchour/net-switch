package winplatform

import (
	"context"
	"math/bits"
	"net"
	"syscall"
	"time"

	"golang.org/x/sys/windows"
)

const ipUnicastIf = 31

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
