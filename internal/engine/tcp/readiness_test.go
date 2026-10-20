package tcp

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/AyoubAchour/net-switch/internal/engine/flows"
	"github.com/AyoubAchour/net-switch/internal/engine/platform"
	"github.com/AyoubAchour/net-switch/internal/engine/policy"
	"github.com/AyoubAchour/net-switch/internal/engine/testfake"
	"gvisor.dev/gvisor/pkg/tcpip"
)

// A nonblocking peer with explicit readiness and short writes exercises the
// common relay state machine in Windows and Linux race jobs alike.
type readyPeer struct {
	platform.TCPConn
	mu                     sync.Mutex
	download, upload       bytes.Buffer
	eof, blocked, detached bool
	wake                   func()
	writeClosed, closed    chan struct{}
	watching               chan struct{}
	writeOnce, closeOnce   sync.Once
}

func newReadyPeer() *readyPeer {
	return &readyPeer{writeClosed: make(chan struct{}), closed: make(chan struct{}), watching: make(chan struct{})}
}
func (p *readyPeer) Watch(wake func()) (platform.Readiness, error) {
	p.mu.Lock()
	p.wake = wake
	p.mu.Unlock()
	close(p.watching)
	return p, nil
}
func (p *readyPeer) Detach() { p.mu.Lock(); p.detached = true; p.mu.Unlock() }
func (p *readyPeer) Arm(read, write bool) error {
	p.mu.Lock()
	wake, ready := p.wake, !p.detached && ((read && (p.download.Len() > 0 || p.eof)) || (write && !p.blocked))
	p.mu.Unlock()
	if ready {
		wake()
	}
	return nil
}
func (p *readyPeer) TryRead(b []byte) (int, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.download.Len() > 0 {
		return p.download.Read(b)
	}
	if p.eof {
		return 0, io.EOF
	}
	return 0, platform.ErrWouldBlock
}
func (p *readyPeer) TryWrite(b []byte) (int, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.blocked {
		return 0, platform.ErrWouldBlock
	}
	return p.upload.Write(b[:min(len(b), 777)])
}
func (*readyPeer) CloseRead() error    { return nil }
func (p *readyPeer) CloseWrite() error { p.writeOnce.Do(func() { close(p.writeClosed) }); return nil }
func (*readyPeer) SetLinger(int) error { return nil }
func (p *readyPeer) Close() error      { p.closeOnce.Do(func() { close(p.closed) }); return nil }
func (*readyPeer) LocalAddr() net.Addr { return &net.TCPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 12345} }

func TestReadyRelayBackpressureShortWritesAndHalfClose(t *testing.T) {
	peer := newReadyPeer()
	peer.blocked = true
	control := &testfake.Controller{Line: "A"}
	_, dial := harness(t, control, testfake.Dialer{TCPFunc: func(context.Context, string, netip.AddrPort) (platform.TCPConn, error) { return peer, nil }})
	app, err := dial()
	if err != nil {
		t.Fatal(err)
	}
	defer app.Close()
	select {
	case <-peer.watching:
	case <-time.After(time.Second):
		t.Fatal("readiness relay was not installed")
	}
	app.SetDeadline(time.Now().Add(5 * time.Second))
	upload := bytes.Repeat([]byte("partial writes remain ordered\n"), 6000)
	writeDone := make(chan error, 1)
	go func() { _, err := app.Write(upload); app.CloseWrite(); writeDone <- err }()
	// The remote starts blocked; no upload can have been counted or discarded.
	time.Sleep(20 * time.Millisecond)
	if control.Up.Load() != 0 {
		t.Fatal("blocked socket counted unwritten bytes")
	}
	peer.mu.Lock()
	peer.blocked = false
	wake := peer.wake
	peer.mu.Unlock()
	wake()
	select {
	case <-peer.writeClosed:
	case <-time.After(5 * time.Second):
		t.Fatal("half-close never followed buffered upload")
	}
	if err := <-writeDone; err != nil {
		t.Fatal(err)
	}
	peer.mu.Lock()
	if !bytes.Equal(peer.upload.Bytes(), upload) {
		peer.mu.Unlock()
		t.Fatal("short writes lost or reordered data")
	}
	download := bytes.Repeat([]byte("response after upload EOF\n"), 9000)
	peer.download.Write(download)
	peer.eof = true
	peer.mu.Unlock()
	wake()
	got, err := io.ReadAll(app)
	if err != nil || !bytes.Equal(got, download) {
		t.Fatalf("half-close response: %d bytes, %v", len(got), err)
	}
	select {
	case <-peer.closed:
	case <-time.After(time.Second):
		t.Fatal("relay did not close")
	}
	if control.Up.Load() != uint64(len(upload)) || control.Down.Load() != uint64(len(download)) {
		t.Fatalf("byte counts: %d/%d", control.Up.Load(), control.Down.Load())
	}
}

func TestReadyRelayIdleCloseByPolicy(t *testing.T) {
	peer := newReadyPeer()
	control := flows.New(flows.Defaults(), nil)
	cfg := policy.Config{Lines: []platform.Line{{ID: "A"}}, IPv6: true}
	if _, err := control.Apply(policy.Revision{N: 1, Hash: policy.Hash(cfg), Config: cfg}); err != nil {
		t.Fatal(err)
	}
	_, dial := harness(t, control, testfake.Dialer{TCPFunc: func(context.Context, string, netip.AddrPort) (platform.TCPConn, error) { return peer, nil }})
	app, err := dial()
	if err != nil {
		t.Fatal(err)
	}
	defer app.Close()
	select {
	case <-peer.watching:
	case <-time.After(time.Second):
		t.Fatal("readiness relay was not installed")
	}
	if result, err := control.CloseFlows(flows.Selector{Line: "A"}, 0); err != nil || result.Closed != 1 {
		t.Fatalf("policy closure: %+v %v", result, err)
	}
	select {
	case <-peer.closed:
	case <-time.After(time.Second):
		t.Fatal("idle relay lost policy cancellation")
	}
}

func TestReadyRelayActiveClosePreservesTimeWait(t *testing.T) {
	peer := newReadyPeer()
	control := flows.New(flows.Defaults(), nil)
	cfg := policy.Config{Lines: []platform.Line{{ID: "A"}}, IPv6: true}
	if _, err := control.Apply(policy.Revision{N: 1, Hash: policy.Hash(cfg), Config: cfg}); err != nil {
		t.Fatal(err)
	}
	f, dial := harness(t, control, testfake.Dialer{TCPFunc: func(context.Context, string, netip.AddrPort) (platform.TCPConn, error) { return peer, nil }})
	app, err := dial()
	if err != nil {
		t.Fatal(err)
	}
	defer app.Close()
	app.SetDeadline(time.Now().Add(2 * time.Second))
	select {
	case <-peer.watching:
	case <-time.After(time.Second):
		t.Fatal("no readiness relay")
	}
	peer.mu.Lock()
	peer.eof = true
	wake := peer.wake
	peer.mu.Unlock()
	wake()
	if data, err := io.ReadAll(app); err != nil || len(data) != 0 {
		t.Fatalf("server FIN: %q %v", data, err)
	}
	if err := app.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-peer.closed:
	case <-time.After(time.Second):
		t.Fatal("relay did not finish")
	}
	if got := control.Stats(); got.TimeWait != 1 || got.Flows != 0 {
		t.Fatalf("normal close lost TIME_WAIT: %+v", got)
	}
	if resets := f.stack.Stats().TCP.ResetsSent.Value(); resets != 0 {
		t.Fatalf("normal close sent %d resets", resets)
	}
}

type readableEndpoint struct {
	tcpip.Endpoint
	data []byte
}

func (e *readableEndpoint) Read(out io.Writer, _ tcpip.ReadOptions) (tcpip.ReadResult, tcpip.Error) {
	if len(e.data) == 0 {
		return tcpip.ReadResult{}, &tcpip.ErrWouldBlock{}
	}
	n, _ := out.Write(e.data)
	e.data = e.data[n:]
	return tcpip.ReadResult{Count: n}, nil
}

func TestBlockedRelayOwnsBytesAcrossWorkerScratchReuse(t *testing.T) {
	control := &testfake.Controller{}
	workers := &relayWorkers{waiting: make(map[*readyRelay]struct{})}
	makeRelay := func(data []byte, peer *readyPeer) *readyRelay {
		ticket, err := control.Begin("tcp", platform.Tuple{})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(ticket.Close)
		return &readyRelay{workers: workers, remote: peer, c: &connection{ep: &readableEndpoint{data: data}, ticket: ticket}}
	}
	firstBytes := bytes.Repeat([]byte("first connection\n"), 500)
	firstPeer := newReadyPeer()
	firstPeer.blocked = true
	first := makeRelay(firstBytes, firstPeer)
	scratch := new(relayScratch)
	if _, err := first.direction(&first.up, true, scratch); err != nil {
		t.Fatal(err)
	}
	if first.up.buffer == nil || firstPeer.upload.Len() != 0 {
		t.Fatal("fixture must retain the first connection's unwritten bytes")
	}
	secondBytes := bytes.Repeat([]byte("second connection uses the same worker\n"), 500)
	secondPeer := newReadyPeer()
	second := makeRelay(secondBytes, secondPeer)
	if _, err := second.direction(&second.up, true, scratch); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(secondPeer.upload.Bytes(), secondBytes) {
		t.Fatal("second connection did not overwrite the worker scratch")
	}
	firstPeer.blocked = false
	if _, err := first.direction(&first.up, true, scratch); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(firstPeer.upload.Bytes(), firstBytes) {
		t.Fatal("worker reuse changed another connection's pending bytes")
	}
	if first.up.buffer != nil || second.up.buffer != nil {
		t.Fatal("drained connections retained their pending buffer")
	}
}

func TestStalledDirectionsStopReadingAtTheirSharedBufferBound(t *testing.T) {
	w := &relayWorkers{waiting: make(map[*readyRelay]struct{}), wake: make(chan struct{}, 1)}
	control := &testfake.Controller{}
	scratch := new(relayScratch)
	var relays []*readyRelay
	for i := 0; i < RelayHeldBudget/RelayBuffer+20; i++ {
		ticket, _ := control.Begin("tcp", platform.Tuple{})
		peer := newReadyPeer()
		peer.blocked = true
		r := &readyRelay{workers: w, remote: peer, c: &connection{ticket: ticket, ep: &readableEndpoint{data: []byte("held")}}}
		relays = append(relays, r)
		if _, err := r.direction(&r.up, true, scratch); err != nil {
			t.Fatal(err)
		}
	}
	if w.loans*RelayBuffer != RelayHeldBudget || len(w.waiting) != 20 {
		t.Fatalf("stalled storage is not bounded: %d loans/%d waiters", w.loans, len(w.waiting))
	}
	last := relays[len(relays)-1]
	if len(last.c.ep.(*readableEndpoint).data) != 4 || last.up.buffer != nil {
		t.Fatal("an unbudgeted read consumed bytes before it could retain them")
	}
	for _, r := range relays {
		r.remote.(*readyPeer).blocked = false
		if _, err := r.direction(&r.up, true, scratch); err != nil {
			t.Fatal(err)
		}
		if string(r.remote.(*readyPeer).upload.Bytes()) != "held" {
			t.Fatal("capacity recovery lost buffered or unread data")
		}
		r.c.ticket.Close()
	}
	if w.loans != 0 {
		t.Fatal("stalled relay loans were not returned")
	}
}
