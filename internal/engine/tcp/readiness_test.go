package tcp

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/AyoubAchour/net-switch/internal/engine/flows"
	"github.com/AyoubAchour/net-switch/internal/engine/platform"
	"github.com/AyoubAchour/net-switch/internal/engine/policy"
	"github.com/AyoubAchour/net-switch/internal/engine/testfake"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
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

type stalledAppOwners struct{ next atomic.Uint64 }

func (o *stalledAppOwners) TCP(context.Context, platform.Tuple) (platform.Owner, error) {
	app := "stalled"
	if o.next.Add(1) > 512 {
		app = "healthy"
	}
	return platform.Owner{AppID: app}, nil
}
func (*stalledAppOwners) UDP(context.Context, netip.AddrPort) (platform.Owner, error) {
	return platform.Owner{}, nil
}

func Test512NonReadingConnectionsDoNotBlockAnotherAppsDataOrFIN(t *testing.T) {
	control := &testfake.Controller{Line: "A"}
	peers := make(chan *readyPeer, 1)
	f, dial := harness(t, control, testfake.Dialer{TCPFunc: func(context.Context, string, netip.AddrPort) (platform.TCPConn, error) {
		p := newReadyPeer()
		peers <- p
		return p, nil
	}})
	f.owners = &stalledAppOwners{}
	var apps []*gonet.TCPConn
	defer func() {
		for _, app := range apps {
			app.Close()
		}
	}()
	var stalled []*readyPeer
	payload := bytes.Repeat([]byte("s"), 256<<10)
	for range 512 {
		app, err := dial()
		if err != nil {
			t.Fatal(err)
		}
		apps = append(apps, app)
		peer := <-peers
		select {
		case <-peer.watching:
		case <-time.After(2 * time.Second):
			t.Fatal("relay setup stalled")
		}
		peer.mu.Lock()
		peer.download.Write(payload)
		wake := peer.wake
		peer.mu.Unlock()
		wake()
		stalled = append(stalled, peer)
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		backpressured := 0
		for _, peer := range stalled {
			peer.mu.Lock()
			left := peer.download.Len()
			peer.mu.Unlock()
			if left > 0 && left < len(payload) {
				backpressured++
			}
		}
		if backpressured == 512 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("fixture only stalled %d/512 receivers", backpressured)
		}
		time.Sleep(time.Millisecond)
	}
	began := time.Now()
	for range 4 {
		app, err := dial()
		if err != nil {
			t.Fatal(err)
		}
		defer app.Close()
		peer := <-peers
		select {
		case <-peer.watching:
		case <-time.After(time.Second):
			t.Fatal("healthy relay setup stalled")
		}
		peer.mu.Lock()
		peer.download.WriteString("healthy data and FIN")
		peer.eof = true
		wake := peer.wake
		peer.mu.Unlock()
		wake()
		app.SetReadDeadline(time.Now().Add(2 * time.Second))
		got, err := io.ReadAll(app)
		if err != nil || string(got) != "healthy data and FIN" {
			t.Fatalf("healthy app stalled: %q %v", got, err)
		}
		app.CloseWrite()
	}
	for _, peer := range stalled {
		peer.mu.Lock()
		remaining := peer.download.Len()
		peer.mu.Unlock()
		if remaining == 0 {
			t.Fatal("stalled fixture drained before healthy probes")
		}
		select {
		case <-peer.closed:
			t.Fatal("stalled app was cut to free capacity")
		default:
		}
	}
	held, peak := f.RelayBufferBytes()
	if peak > RelayHeldBudget {
		t.Fatal("relay exceeded byte budget")
	}
	t.Logf("512 non-reading gVisor connections remain open; 4 healthy downloads and FIN completed in %s; loans=%d bytes peak=%d", time.Since(began), held, peak)
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
func (p *readyPeer) TryPeek(b []byte) (int, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.download.Len() > 0 {
		return copy(b, p.download.Bytes()), nil
	}
	if p.eof {
		return 0, io.EOF
	}
	return 0, platform.ErrWouldBlock
}
func (p *readyPeer) TryDiscard(b []byte) (int, error) { return p.TryRead(b) }
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
	eof  bool
}

func (e *readableEndpoint) Read(out io.Writer, opts tcpip.ReadOptions) (tcpip.ReadResult, tcpip.Error) {
	if len(e.data) == 0 {
		if e.eof {
			return tcpip.ReadResult{}, &tcpip.ErrClosedForReceive{}
		}
		return tcpip.ReadResult{}, &tcpip.ErrWouldBlock{}
	}
	n, _ := out.Write(e.data)
	if !opts.Peek {
		e.data = e.data[n:]
	}
	return tcpip.ReadResult{Count: n}, nil
}
func (e *readableEndpoint) Shutdown(tcpip.ShutdownFlags) tcpip.Error { return nil }

func TestBlockedRelayOwnsBytesAcrossWorkerScratchReuse(t *testing.T) {
	w := &relayWorkers{}
	control := &testfake.Controller{}
	makeRelay := func(data []byte, peer *readyPeer) *readyRelay {
		ticket, _ := control.Begin("tcp", platform.Tuple{})
		t.Cleanup(ticket.Close)
		return &readyRelay{workers: w, remote: peer, c: &connection{ticket: ticket, ep: &readableEndpoint{data: data}}}
	}
	firstBytes := bytes.Repeat([]byte("first connection\n"), 500)
	firstPeer := newReadyPeer()
	firstPeer.blocked = true
	first := makeRelay(firstBytes, firstPeer)
	scratch := new(relayScratch)
	if _, err := first.direction(&first.up, true, scratch); err != nil {
		t.Fatal(err)
	}
	if w.loans != 0 || !bytes.Equal(first.c.ep.(*readableEndpoint).data, firstBytes) {
		t.Fatal("stall consumed source data or retained a loan")
	}
	secondBytes := bytes.Repeat([]byte("second connection\n"), 500)
	secondPeer := newReadyPeer()
	second := makeRelay(secondBytes, secondPeer)
	if _, err := second.direction(&second.up, true, scratch); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(secondPeer.upload.Bytes(), secondBytes) {
		t.Fatal("second connection failed")
	}
	firstPeer.blocked = false
	if _, err := first.direction(&first.up, true, scratch); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(firstPeer.upload.Bytes(), firstBytes) {
		t.Fatal("scratch reuse corrupted source")
	}
}

func TestStalledDirectionsStopReadingAtTheirSharedBufferBound(t *testing.T) {
	w := &relayWorkers{}
	control := &testfake.Controller{}
	scratch := new(relayScratch)
	for i := 0; i < 532; i++ {
		ticket, _ := control.Begin("tcp", platform.Tuple{})
		peer := newReadyPeer()
		peer.blocked = true
		ep := &readableEndpoint{data: []byte("held")}
		r := &readyRelay{workers: w, remote: peer, c: &connection{ticket: ticket, ep: ep}}
		if _, err := r.direction(&r.up, true, scratch); err != nil {
			t.Fatal(err)
		}
		if w.loans != 0 || string(ep.data) != "held" {
			t.Fatal("stall retained loan or consumed source")
		}
		peer.blocked = false
		if _, err := r.direction(&r.up, true, scratch); err != nil {
			t.Fatal(err)
		}
		if peer.upload.String() != "held" {
			t.Fatal("recovery lost data")
		}
		ticket.Close()
	}
	if w.bufferPeak*RelayBuffer > RelayHeldBudget {
		t.Fatal("shared budget exceeded")
	}
}

func TestRelayLoanFIFOAndAppLimit(t *testing.T) {
	w := &relayWorkers{wake: make(chan struct{}, 1)}
	holders := make([]*readyRelay, RelayAppLoans)
	for i := range holders {
		holders[i] = &readyRelay{workers: w, app: "slow"}
		if !w.borrow(holders[i]) {
			t.Fatal("early refusal")
		}
	}
	waiter := &readyRelay{workers: w, app: "slow"}
	if w.borrow(waiter) {
		t.Fatal("per-app loan cap exceeded")
	}
	healthy := &readyRelay{workers: w, app: "healthy"}
	if w.borrow(healthy) {
		t.Fatal("new caller skipped FIFO")
	}
	if !w.borrow(healthy) {
		t.Fatal("eligible other app was not granted")
	}
	w.giveBack(healthy)
	for i := 0; i < 100; i++ {
		holder := holders[0]
		w.giveBack(holder)
		if w.borrow(holder) {
			t.Fatal("slow holder overtook queued waiter")
		}
		if !w.borrow(waiter) {
			t.Fatal("waiter starved")
		}
		w.giveBack(waiter)
		if !w.borrow(holder) {
			t.Fatal("holder never resumed")
		}
		if w.borrow(waiter) {
			t.Fatal("waiter exceeded the per-app cap")
		}
	}
	waiter.closed.Store(true)
	for _, r := range holders {
		w.giveBack(r)
	}
	if w.loans != 0 || len(w.waiting) != 0 {
		t.Fatal("loans leaked")
	}
}

func TestRelayGlobalLoanBoundReservesFreedSlotForFIFOHead(t *testing.T) {
	w := &relayWorkers{wake: make(chan struct{}, 1)}
	holders := make([]*readyRelay, RelayHeldBudget/RelayBuffer)
	for i := range holders {
		holders[i] = &readyRelay{workers: w, app: string(rune('a' + i/RelayAppLoans))}
		if !w.borrow(holders[i]) {
			t.Fatal("capacity refused too early")
		}
	}
	waiter := &readyRelay{workers: w, app: "new app"}
	if w.borrow(waiter) || w.loans*RelayBuffer != RelayHeldBudget {
		t.Fatal("global loan bound exceeded")
	}
	w.giveBack(holders[0])
	if w.borrow(holders[0]) {
		t.Fatal("returning holder stole FIFO reservation")
	}
	if !w.borrow(waiter) {
		t.Fatal("FIFO waiter did not receive reserved capacity")
	}
	w.giveBack(waiter)
	if !w.borrow(holders[0]) {
		t.Fatal("previous holder never resumed")
	}
	for _, r := range holders {
		w.giveBack(r)
	}
	if w.loans != 0 || w.bufferPeak*RelayBuffer != RelayHeldBudget {
		t.Fatal("loan accounting leaked or exceeded bound")
	}
}

func TestStalledAppCannotFreezeHealthyRelay(t *testing.T) {
	w := &relayWorkers{wake: make(chan struct{}, 1)}
	control := &testfake.Controller{}
	scratch := new(relayScratch)
	var stalled []*readyRelay
	for i := 0; i < 512; i++ {
		ticket, _ := control.Begin("tcp", platform.Tuple{})
		t.Cleanup(ticket.Close)
		peer := newReadyPeer()
		peer.blocked = true
		r := &readyRelay{workers: w, app: "stalled", remote: peer, c: &connection{ticket: ticket, ep: &readableEndpoint{data: []byte("stalled")}}}
		stalled = append(stalled, r)
		if _, err := r.direction(&r.up, true, scratch); err != nil {
			t.Fatal(err)
		}
	}
	for i := 0; i < 16; i++ {
		ticket, _ := control.Begin("tcp", platform.Tuple{})
		t.Cleanup(ticket.Close)
		peer := newReadyPeer()
		r := &readyRelay{workers: w, app: "healthy", remote: peer, c: &connection{ticket: ticket, ep: &readableEndpoint{data: []byte("healthy"), eof: true}}}
		began := time.Now()
		if _, err := r.direction(&r.up, true, scratch); err != nil {
			t.Fatal(err)
		}
		if peer.upload.String() != "healthy" || !r.up.finished || time.Since(began) > time.Second {
			t.Fatal("healthy data or FIN stalled")
		}
	}
	for _, r := range stalled {
		if !r.up.blocked || string(r.c.ep.(*readableEndpoint).data) != "stalled" {
			t.Fatal("fixture did not keep stalled peers open")
		}
	}
	t.Logf("512 stalled flows remain open; 16 healthy flows delivered data and FIN; loans=%d/512 peak=%d", w.loans, w.bufferPeak)
}
