package winplatform

import (
	"context"
	"math/bits"
	"net"
	"net/http"
	"syscall"

	"github.com/AyoubAchour/net-switch/internal/control/engine"
	"github.com/AyoubAchour/net-switch/internal/linecheck"
	"golang.org/x/sys/windows"
)

func checkLine(index uint32, target string, quick bool) engine.ProbeResult {
	adapter, err := net.InterfaceByIndex(int(index))
	if err != nil {
		return engine.ProbeResult{Outcome: engine.Unavailable}
	}
	addresses, err := adapter.Addrs()
	if err != nil {
		return engine.ProbeResult{Outcome: engine.Unavailable}
	}
	var local net.IP
	for _, a := range addresses {
		ip, _, err := net.ParseCIDR(a.String())
		if err == nil && ip.To4() != nil && !ip.IsLoopback() && !ip.IsLinkLocalUnicast() {
			local = ip.To4()
			break
		}
	}
	if local == nil {
		return engine.ProbeResult{Outcome: engine.Unavailable}
	}
	dialer := &net.Dialer{LocalAddr: &net.TCPAddr{IP: local}, Control: func(_, _ string, raw syscall.RawConn) error {
		var socketErr error
		err := raw.Control(func(fd uintptr) {
			socketErr = windows.SetsockoptInt(windows.Handle(fd), windows.IPPROTO_IP, ipUnicastIf, int(bits.ReverseBytes32(index)))
		})
		if err != nil {
			return err
		}
		return socketErr
	}}
	if quick {
		return linecheck.TCP(context.Background(), target, dialer.DialContext)
	}
	transport := &http.Transport{DialContext: dialer.DialContext, ForceAttemptHTTP2: true, DisableKeepAlives: true}
	defer transport.CloseIdleConnections()
	return linecheck.HTTPS(context.Background(), target, transport)
}
