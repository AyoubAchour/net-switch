package engine

import (
	"context"
	"errors"
	"net"
	"net/netip"

	"github.com/AyoubAchour/net-switch/internal/engine/flows"
	"github.com/AyoubAchour/net-switch/internal/engine/testproxy"
)

func (e *Engine) StartTestProxy(_ context.Context, address string) (testproxy.Status, error) {
	if !testproxy.Enabled {
		return testproxy.Status{}, testproxy.ErrDisabled
	}
	a, err := netip.ParseAddrPort(address)
	if err != nil || !a.Addr().IsLoopback() || a.Addr().Zone() != "" {
		return testproxy.Status{}, errors.New("test proxy requires a literal loopback address")
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.stack == nil {
		return testproxy.Status{}, flows.ErrStopped
	}
	if e.testProxy != nil {
		return e.testProxy.Status(), nil
	}
	dial := func(ctx context.Context, line string, dst netip.AddrPort) (net.Conn, error) {
		return e.deps.Dialer.DialTCP(ctx, line, dst)
	}
	// Windows' relay sockets belong to native readiness; the test proxy uses
	// the same bound Go-connection path as HTTPS probes, without transferring it.
	if d, ok := e.deps.Dialer.(interface {
		DialTestTCP(context.Context, string, netip.AddrPort) (net.Conn, error)
	}); ok {
		dial = d.DialTestTCP
	}
	s, err := testproxy.New(e.root, testproxy.Options{Address: address, Table: e.Table, Owners: e.deps.Owners, Dial: dial})
	if err != nil {
		return testproxy.Status{}, err
	}
	e.testProxy = s
	return s.Status(), nil
}
