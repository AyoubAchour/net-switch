package tcp

import (
	"context"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/AyoubAchour/net-switch/internal/engine/flowapi"
	"github.com/AyoubAchour/net-switch/internal/engine/flows"
	"github.com/AyoubAchour/net-switch/internal/engine/platform"
	"github.com/AyoubAchour/net-switch/internal/engine/policy"
	"github.com/AyoubAchour/net-switch/internal/engine/testfake"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

type setupCancelControl struct {
	*flows.Table
	buffers func()
	closed  chan struct{}
}

func (c *setupCancelControl) Begin(proto string, tuple platform.Tuple) (flowapi.Ticket, error) {
	t, err := c.Table.Begin(proto, tuple)
	if err != nil {
		return nil, err
	}
	return &setupCancelTicket{Ticket: t, control: c}, nil
}

type setupCancelTicket struct {
	flowapi.Ticket
	control *setupCancelControl
}

func (t *setupCancelTicket) Buffers() (int, int) {
	if t.control.buffers != nil {
		t.control.buffers()
	}
	return t.Ticket.Buffers()
}

func (t *setupCancelTicket) Close() {
	t.Ticket.Close()
	close(t.control.closed)
}

func TestCancelDuringEndpointSetup(t *testing.T) {
	for _, where := range []string{"close_during_handshake", "stop_during_setup"} {
		t.Run(where, func(t *testing.T) {
			c := &setupCancelControl{Table: flows.New(flows.Defaults(), nil), closed: make(chan struct{})}
			config := policy.Config{Lines: []platform.Line{{ID: "A"}}, IPv6: true}
			if _, err := c.Apply(policy.Revision{N: 1, Hash: policy.Hash(config), Config: config}); err != nil {
				t.Fatal(err)
			}
			remote, server := testfake.Pair()
			defer server.Close()
			d := testfake.Dialer{TCPFunc: func(context.Context, string, netip.AddrPort) (platform.TCPConn, error) {
				return remote, nil
			}}
			var cancelOnce sync.Once
			f, dial := harnessPackets(t, c, d, func(f *Forwarder, raw []byte) {
				h := header.TCP(raw[header.IPv4(raw).HeaderLength():])
				if where == "close_during_handshake" && h.Flags().Contains(header.TCPFlagSyn|header.TCPFlagAck) {
					// Cancel before delivering SYN-ACK. CreateEndpoint still finishes
					// the handshake, then observes this cancellation on return.
					cancelOnce.Do(func() {
						result, err := c.CloseFlows(flows.Selector{Line: "A"}, 0)
						if err != nil || result.Closed != 1 {
							t.Errorf("close during handshake: %+v, %v", result, err)
						}
					})
				}
			})
			if where == "stop_during_setup" {
				c.buffers = f.Stop
			}
			app, err := dial()
			if app != nil {
				defer app.Close()
			}
			if err != nil {
				t.Fatal("handshake should complete before endpoint abort", err)
			}
			select {
			case <-c.closed:
			case <-time.After(time.Second):
				t.Fatal("cancelled setup did not release its ticket")
			}
			if resets := f.stack.Stats().TCP.ResetsSent.Value(); resets != 1 {
				t.Errorf("setup cancellation sent %d resets, want 1", resets)
			}
			if g := c.Stats(); g.Rejected != 0 || g.Flows != 0 || g.Handshakes != 0 || f.Rejected.Load() != 0 {
				t.Error("cancelled setup counted as rejection or leaked", g)
			}
			for {
				select {
				case event := <-c.Events():
					if event.Message == "flow rejected" {
						t.Error("cancelled setup logged flow rejected")
					}
				default:
					return
				}
			}
		})
	}
}
