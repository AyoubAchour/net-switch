package tcp

import (
	"context"
	"errors"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/AyoubAchour/net-switch/internal/engine/flowapi"
	"github.com/AyoubAchour/net-switch/internal/engine/platform"
	"github.com/AyoubAchour/net-switch/internal/engine/testfake"
	gv "gvisor.dev/gvisor/pkg/tcpip/stack"
	gtcp "gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
)

type heldBuffersControl struct {
	*testfake.Controller
	entered, release chan struct{}
}

func (c *heldBuffersControl) Begin(proto string, tuple platform.Tuple) (flowapi.Ticket, error) {
	t, err := c.Controller.Begin(proto, tuple)
	return &heldBuffersTicket{Ticket: t, entered: c.entered, release: c.release}, err
}

type heldBuffersTicket struct {
	flowapi.Ticket
	entered, release chan struct{}
}

func (t *heldBuffersTicket) Buffers() (int, int) {
	close(t.entered)
	<-t.release
	return t.Ticket.Buffers()
}

func TestReopenHookDuringEndpointSetupDeduplicates(t *testing.T) {
	c := &heldBuffersControl{Controller: &testfake.Controller{}, entered: make(chan struct{}), release: make(chan struct{})}
	defer close(c.release)
	var dials atomic.Int32
	remote := make(chan *testfake.Conn, 1)
	d := testfake.Dialer{TCPFunc: func(context.Context, string, netip.AddrPort) (platform.TCPConn, error) {
		if dials.Add(1) != 1 {
			return nil, errors.New("duplicate dial")
		}
		a, b := testfake.Pair()
		remote <- b
		return a, nil
	}}
	f, dial := harness(t, c, d)
	type syn struct {
		id  gv.TransportEndpointID
		pkt *gv.PacketBuffer
	}
	saved := make(chan syn, 1)
	var once sync.Once
	f.stack.SetTransportProtocolHandler(gtcp.ProtocolNumber, func(id gv.TransportEndpointID, pkt *gv.PacketBuffer) bool {
		once.Do(func() { saved <- syn{id, pkt.IncRef()} })
		return f.Handle(id, pkt)
	})
	app, err := dial()
	if err != nil {
		t.Fatal(err)
	}
	defer app.Close()
	defer (<-remote).Close()
	first := <-saved
	defer first.pkt.DecRef()
	select {
	case <-c.entered:
	case <-time.After(time.Second):
		t.Fatal("endpoint setup barrier not reached")
	}
	// A delayed TIME_WAIT hook can arrive after the new handshake but before
	// the relay is registered. Admission must cover that entire setup period.
	f.Handle(first.id, first.pkt)
	if c.Begun.Load() != 1 {
		t.Fatal("hook readmitted during endpoint setup", c.Begun.Load())
	}
}
