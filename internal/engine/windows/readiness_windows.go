//go:build windows

package winengine

import (
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"runtime"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/AyoubAchour/net-switch/internal/engine/platform"
	"github.com/AyoubAchour/net-switch/internal/winclock"
	"github.com/AyoubAchour/net-switch/internal/winhandle"
	"golang.org/x/sys/windows"
)

var winsock = windows.NewLazySystemDLL("ws2_32.dll")

// The shared relay consumes readiness, not blocking reads. Every outbound TCP
// socket is associated with this one completion port when it is created: its
// ConnectEx completes here, and once connected an idle socket posts a zero-byte
// overlapped receive here. No payload buffer and no goroutine per socket. Only
// backpressured writers use WSAPoll.
type readiness struct {
	mu          sync.Mutex
	port        winhandle.Owner
	next        uintptr
	watches     map[uintptr]*socketWatch
	writers     map[uintptr]*socketWatch
	stop        chan struct{}
	wg          sync.WaitGroup
	thread      atomic.Uint32
	capture     bool
	closes      [1024]nativeSocketClose
	closedCount uint64
	poll        func([]pollFD) int32
	policy      tcpCompletionPolicy
	cancel      func(windows.Handle, *windows.Overlapped) error
	providerIFS func(winhandle.Owner) (bool, error)
	nonIFS      atomic.Uint64 // sockets whose own provider refused skip-success
	providerErr atomic.Pointer[providerFailure]
	immediate   atomic.Uint64
	submitted   atomic.Uint64
	completed   atomic.Uint64
	connects    atomic.Uint64
	pendingConn atomic.Uint64
}

type providerFailure struct {
	count uint64
	err   string
}

type nativeSocketClose struct {
	Sequence uint64         `json:"sequence"`
	Local    netip.AddrPort `json:"local"`
	Handle   uint64         `json:"handle"`
	Error    string         `json:"error,omitempty"`
}

// socketWatch is the heap owner of everything the kernel may hold for one
// socket: the OVERLAPPED shared by ConnectEx and the receive readiness, the
// receive flags, and ConnectEx's destination and byte count. It lives from the
// socket's creation until Detach, and op stays pinned for that whole time.
type socketWatch struct {
	mu                       sync.Mutex
	pool                     *readiness
	socket                   winhandle.Owner
	key                      uintptr
	localPort                uint16 // diagnostics: set once under pool.mu after connecting
	remote                   string // diagnostics: the peer, set with localPort
	established              bool   // pool.mu
	wake                     func()
	op                       windows.Overlapped
	flags                    uint32
	name                     [16]uint64 // SOCKADDR_STORAGE size and alignment
	sent                     uint32
	connected                chan struct{} // closed by ConnectEx's completion packet
	connecting               bool
	pin                      runtime.Pinner
	pending, detached, write bool
	drained                  chan struct{}
	detachDone               chan struct{}
	detachErr                error
	skipSuccess              bool
}

func newReadiness() (*readiness, error) {
	return newReadinessWithPolicy(queryTCPCompletionPolicy(windows.WSAEnumProtocols))
}

func newReadinessWithPolicy(policy tcpCompletionPolicy) (*readiness, error) {
	port, err := windows.CreateIoCompletionPort(windows.InvalidHandle, 0, 0, 1)
	if err != nil {
		return nil, err
	}
	p := &readiness{
		port:    winhandle.Open(port, "TCP completion port open"),
		watches: map[uintptr]*socketWatch{}, writers: map[uintptr]*socketWatch{},
		stop: make(chan struct{}), capture: hostedTraceEnabled(), poll: pollWritable,
		policy: policy, cancel: windows.CancelIoEx, providerIFS: socketProviderIFS,
	}
	p.wg.Go(p.completions)
	p.wg.Go(p.pollWrites)
	return p, nil
}

func (p *readiness) completions() {
	// IOCP association belongs to an OS thread, not a goroutine. Without
	// pinning, unrelated Go work can keep that thread counted against this
	// port's concurrency limit and delay later completion/cancellation packets.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	p.thread.Store(windows.GetCurrentThreadId())
	for {
		var count uint32
		var key uintptr
		var op *windows.Overlapped
		err := windows.GetQueuedCompletionStatus(p.port.Handle("TCP completion wait"), &count, &key, &op, windows.INFINITE)
		if op == nil {
			if key == 0 {
				return
			}
			continue
		}
		p.mu.Lock()
		w := p.watches[key]
		p.mu.Unlock()
		if w == nil {
			panic("completion lost its live socket registration")
		}
		w.mu.Lock()
		if op != &w.op || !w.pending {
			panic("unexpected socket completion")
		}
		w.pending = false
		p.completed.Add(1)
		if w.connecting {
			// The dialer reads ConnectEx's result from op after this packet.
			w.connecting = false
			close(w.connected)
			w.mu.Unlock()
			continue
		}
		detached := w.detached
		if w.drained != nil {
			close(w.drained)
			w.drained = nil
		}
		wake := w.wake
		w.mu.Unlock()
		// recv reports EOF/reset on the next TryRead. A cancelled operation
		// after Detach has no callback, and its memory is now safe to unpin.
		_ = err
		if !detached && wake != nil {
			wake()
		}
	}
}

func (p *readiness) stats() map[string]any {
	p.mu.Lock()
	defer p.mu.Unlock()
	ports := make([]uint16, 0, len(p.watches))
	// A local port number alone can name a new connection to another peer
	// while the released one is in TIME_WAIT, so the ports are also grouped
	// by peer. Grouped, not one string per watch: at capacity the stats reply
	// must stay under the control channel's 1 MiB cap (run 39597923669).
	peers := map[string][]uint16{}
	normal, skipped, connecting := 0, 0, 0
	for _, watch := range p.watches {
		if watch.skipSuccess {
			skipped++
		} else {
			normal++
		}
		if !watch.established {
			connecting++
			continue
		}
		ports = append(ports, watch.localPort)
		peers[watch.remote] = append(peers[watch.remote], watch.localPort)
	}
	closes := make([]nativeSocketClose, 0, min(p.closedCount, uint64(len(p.closes))))
	for i := p.closedCount - uint64(cap(closes)); i < p.closedCount; i++ {
		closes = append(closes, p.closes[i%uint64(len(p.closes))])
	}
	queryError := ""
	if p.policy.err != nil {
		queryError = p.policy.err.Error()
	}
	var providerErrors uint64
	providerError := ""
	if failure := p.providerErr.Load(); failure != nil {
		providerErrors, providerError = failure.count, failure.err
	}
	return map[string]any{
		"sockets": len(ports), "connectingSockets": connecting, "ports": ports, "peers": peers,
		"blockedWriters": len(p.writers), "completionThread": p.thread.Load(), "closes": closes,
		"closedCount": p.closedCount, "completionPolicy": p.policy.reason,
		"allowSkipCompletionOnSuccess": p.policy.allowSkip, "protocolCatalogEntries": p.policy.entries,
		"nonIFSProvider": p.policy.nonIFS, "providerQueryError": queryError,
		"nonIFSSocketProviders": p.nonIFS.Load(), "socketProviderQueryErrors": providerErrors,
		"socketProviderQueryError": providerError, "normalCompletionSockets": normal,
		"skipSuccessSockets": skipped, "connects": p.connects.Load(), "pendingConnects": p.pendingConn.Load(),
		"immediateReceiveSuccesses": p.immediate.Load(), "asyncReceiveSubmissions": p.submitted.Load(),
		"completionPackets": p.completed.Load(),
	}
}

func (p *readiness) recordClose(local netip.AddrPort, handle windows.Handle, err error) {
	if !p.capture {
		return
	}
	record := nativeSocketClose{Local: local, Handle: uint64(handle)}
	if err != nil {
		record.Error = err.Error()
	}
	p.mu.Lock()
	record.Sequence = p.closedCount + 1
	p.closes[p.closedCount%uint64(len(p.closes))] = record
	p.closedCount++
	p.mu.Unlock()
}

type pollFD struct {
	Socket           windows.Handle
	Events, Returned int16
}

func pollWritable(rows []pollFD) int32 {
	n, _, _ := winsock.NewProc("WSAPoll").Call(uintptr(unsafe.Pointer(&rows[0])), uintptr(len(rows)), 0)
	return int32(n)
}

func (p *readiness) pollWrites() {
	var rows []pollFD
	var watches []*socketWatch
	for {
		if !winclock.System.WaitDone(p.stop, 2*time.Millisecond) {
			return
		}
		// The backing array outlives this snapshot. Release detached watches
		// and their relay callbacks before shortening it, including idle passes.
		clear(watches)
		rows, watches = rows[:0], watches[:0]
		p.mu.Lock()
		for _, w := range p.writers {
			rows = append(rows, pollFD{Socket: w.socket.Handle("TCP write poll snapshot"), Events: pollWrNorm})
			watches = append(watches, w)
		}
		if len(rows) == 0 {
			p.mu.Unlock()
			continue
		}
		for _, w := range watches {
			w.socket.Handle("TCP write poll call")
		}
		// Detach removes the writer under this same mutex before its owner
		// closes the socket. Keep the borrow through the nonblocking query,
		// not just through copying the numeric values into rows.
		n := p.poll(rows)
		p.mu.Unlock()
		if n <= 0 {
			continue
		}
		for i, row := range rows {
			if row.Returned == 0 {
				continue
			}
			w := watches[i]
			w.mu.Lock()
			notify := !w.detached && w.write
			w.write = false
			p.mu.Lock()
			delete(p.writers, w.key)
			p.mu.Unlock()
			wake := w.wake
			w.mu.Unlock()
			if notify {
				wake()
			}
		}
	}
}

// register associates a socket the engine has just created with this port,
// once, before any overlapped call on it. The engine created the socket, so
// its completion mode is exactly what is set here, and nothing has to be read
// back. Skip-on-success is set only when every catalog provider returned IFS
// handles at startup and the socket's own provider still does now.
func (p *readiness) register(socket winhandle.Owner) (*socketWatch, error) {
	skip := false
	if p.policy.allowSkip {
		ifs, err := p.providerIFS(socket)
		switch {
		case err != nil:
			// Normal notifications are always correct; record why skip was not used.
			for {
				old := p.providerErr.Load()
				next := &providerFailure{count: 1, err: err.Error()}
				if old != nil {
					next.count = old.count + 1
				}
				if p.providerErr.CompareAndSwap(old, next) {
					break
				}
			}
		case !ifs:
			p.nonIFS.Add(1)
		default:
			skip = true
		}
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.next++
	w := &socketWatch{pool: p, socket: socket, key: p.next, connected: make(chan struct{})}
	if _, err := windows.CreateIoCompletionPort(socket.Handle("TCP completion attach socket"), p.port.Handle("TCP completion attach port"), w.key, 0); err != nil {
		return nil, fmt.Errorf("TCP completion port association: %w", err)
	}
	if skip {
		if err := windows.SetFileCompletionNotificationModes(socket.Handle("TCP completion modes"),
			windows.FILE_SKIP_COMPLETION_PORT_ON_SUCCESS|windows.FILE_SKIP_SET_EVENT_ON_HANDLE); err != nil {
			return nil, fmt.Errorf("TCP set completion modes: %w", err)
		}
		w.skipSuccess = true
	}
	w.pin.Pin(&w.op)
	p.watches[w.key] = w
	return w, nil
}

func (w *socketWatch) Arm(read, write bool) error {
	w.mu.Lock()
	if w.detached {
		w.mu.Unlock()
		return net.ErrClosed
	}
	w.write = write
	w.pool.mu.Lock()
	if write {
		w.pool.writers[w.key] = w
	} else {
		delete(w.pool.writers, w.key)
	}
	w.pool.mu.Unlock()
	if !read || w.pending {
		w.mu.Unlock()
		return nil
	}
	w.op = windows.Overlapped{}
	w.flags = 0
	w.pending = true
	buf := windows.WSABuf{}
	err := windows.WSARecv(w.socket.Handle("TCP receive readiness arm"), &buf, 1, nil, &w.flags, &w.op, nil)
	if errors.Is(err, windows.ERROR_IO_PENDING) {
		w.pool.submitted.Add(1)
		w.mu.Unlock()
		return nil
	}
	if err == nil {
		w.pool.immediate.Add(1)
		if !w.skipSuccess {
			// Ordinary notifications include synchronous success. The packet
			// still owns op: only completions may clear pending and wake it.
			w.mu.Unlock()
			return nil
		}
	}
	w.pending = false
	wake := w.wake
	w.mu.Unlock()
	if err == nil {
		wake()
	}
	return err
}

func (w *socketWatch) Detach() {
	w.mu.Lock()
	if w.detached {
		done, err := w.detachDone, w.detachErr
		w.mu.Unlock()
		if err != nil {
			panic(err)
		}
		// A concurrent Detach must not let Close recycle the handle while
		// the first caller is still waiting for its cancellation packet.
		<-done
		return
	}
	w.detached = true
	w.detachDone = make(chan struct{})
	w.pool.mu.Lock()
	delete(w.pool.writers, w.key)
	w.pool.mu.Unlock()
	var drained chan struct{}
	if w.pending {
		drained = make(chan struct{})
		w.drained = drained
		h := w.socket.Handle("TCP readiness cancel")
		if err := w.pool.cancel(h, &w.op); err != nil && !errors.Is(err, windows.ERROR_NOT_FOUND) {
			// No safe recovery exists in Detach's void API: returning would
			// permit Close/reuse while the kernel owns op; waiting could hang
			// forever after a failed cancel. Treat this as process-fatal, with
			// the registration and pin intact until exit. Do not recover it.
			w.detachErr = fmt.Errorf("TCP readiness CancelIoEx handle=%#x key=%d skipSuccess=%t: %w", h, w.key, w.skipSuccess, err)
			err := w.detachErr
			w.mu.Unlock()
			panic(err)
		}
		// ERROR_NOT_FOUND means completion won the race. Its queued packet
		// still has to drain before op is unpinned or the socket is closed.
	}
	w.mu.Unlock()
	if drained != nil {
		<-drained
	}
	w.pool.mu.Lock()
	delete(w.pool.watches, w.key)
	w.pool.mu.Unlock()
	w.pin.Unpin()
	close(w.detachDone)
}

func (p *readiness) close() error {
	p.mu.Lock()
	n := len(p.watches)
	p.mu.Unlock()
	if n != 0 {
		return errors.New("cannot close readiness with live sockets")
	}
	close(p.stop)
	windows.PostQueuedCompletionStatus(p.port.Handle("TCP completion stop"), 0, 0, nil)
	p.wg.Wait()
	return p.port.HandleClose("TCP completion port close")
}

// errRelayOnly answers net.Conn's blocking calls. Every engine TCP socket
// belongs to the relay from birth; health probes dial their own Go
// connections (dialProbe), which are never handed to the relay.
var errRelayOnly = errors.New("Windows engine TCP sockets carry relay readiness I/O only")

type readySocket struct {
	mu            sync.Mutex
	handle        winhandle.Owner
	pool          *readiness
	watch         *socketWatch // registered since creation; handed out by Watch
	watched       bool
	local, remote net.Addr
	closed        bool
}

func (c *readySocket) Watch(wake func()) (platform.Readiness, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed || c.watched {
		return nil, net.ErrClosed
	}
	// The socket has been on the completion port since it was created, so
	// handing it to the relay copies and re-registers nothing.
	c.watch.mu.Lock()
	c.watch.wake = wake
	c.watch.mu.Unlock()
	c.watched = true
	return c.watch, nil
}

func socketIO(h winhandle.Owner, name string, b []byte) (int, error) {
	return socketIOFlags(h, name, b, 0)
}

func socketIOFlags(h winhandle.Owner, name string, b []byte, flags uint32) (int, error) {
	if len(b) == 0 {
		return 0, nil
	}
	site := "TCP send"
	if name == "recv" {
		site = "TCP receive"
		if flags != 0 {
			site = "TCP peek"
		}
	}
	n, _, err := winsock.NewProc(name).Call(uintptr(h.Handle(site)), uintptr(unsafe.Pointer(&b[0])), uintptr(len(b)), uintptr(flags))
	runtime.KeepAlive(b)
	if int32(n) == -1 {
		if errors.Is(err, windows.WSAEWOULDBLOCK) {
			return 0, platform.ErrWouldBlock
		}
		return 0, err
	}
	if n == 0 && name == "recv" {
		return 0, io.EOF
	}
	return int(n), nil
}
func (c *readySocket) TryRead(b []byte) (int, error) {
	return c.tryReceive(b, 0)
}

func (c *readySocket) TryPeek(b []byte) (int, error) {
	// recv is synchronous here, with FIONBIO set. This is the documented
	// non-overlapped MSG_PEEK path; no receive buffer outlives the syscall.
	return c.tryReceive(b, 2) // MSG_PEEK.
}

func (c *readySocket) TryDiscard(scratch []byte) (int, error) {
	// The shared relay is the exclusive reader and supplies only the prefix
	// already accepted by the destination. Never consume past that length.
	return c.tryReceive(scratch, 0)
}

func (c *readySocket) tryReceive(b []byte, flags uint32) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed || !c.watched {
		return 0, net.ErrClosed
	}
	return socketIOFlags(c.handle, "recv", b, flags)
}
func (c *readySocket) TryWrite(b []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed || !c.watched {
		return 0, net.ErrClosed
	}
	return socketIO(c.handle, "send", b)
}
func (c *readySocket) Read([]byte) (int, error)         { return 0, errRelayOnly }
func (c *readySocket) Write([]byte) (int, error)        { return 0, errRelayOnly }
func (c *readySocket) LocalAddr() net.Addr              { return c.local }
func (c *readySocket) RemoteAddr() net.Addr             { return c.remote }
func (c *readySocket) SetDeadline(time.Time) error      { return errRelayOnly }
func (c *readySocket) SetReadDeadline(time.Time) error  { return errRelayOnly }
func (c *readySocket) SetWriteDeadline(time.Time) error { return errRelayOnly }
func (c *readySocket) SetLinger(seconds int) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return net.ErrClosed
	}
	var linger windows.Linger
	if seconds >= 0 {
		linger.Onoff, linger.Linger = 1, int32(seconds)
	}
	return windows.SetsockoptLinger(c.handle.Handle("TCP linger"), windows.SOL_SOCKET, windows.SO_LINGER, &linger)
}
func (c *readySocket) shutdown(how int) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return net.ErrClosed
	}
	return windows.Shutdown(c.handle.Handle("TCP shutdown"), how)
}
func (c *readySocket) CloseRead() error  { return c.shutdown(windows.SHUT_RD) }
func (c *readySocket) CloseWrite() error { return c.shutdown(windows.SHUT_WR) }
func (c *readySocket) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil
	}
	c.closed = true
	// Cancel and drain any receive, and leave the port's registration, before
	// the only handle is closed.
	c.watch.Detach()
	h := c.handle.Handle("TCP final close ownership")
	err := c.handle.SocketClose("TCP native socket close")
	c.pool.recordClose(c.local.(*net.TCPAddr).AddrPort(), h, err)
	return err
}

var _ platform.ReadyTCP = (*readySocket)(nil)
