//go:build windows

package winengine

import (
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"runtime"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	"github.com/AyoubAchour/net-switch/internal/engine/platform"
	"github.com/AyoubAchour/net-switch/internal/winclock"
	"github.com/AyoubAchour/net-switch/internal/winhandle"
	"golang.org/x/sys/windows"
)

var winsock = windows.NewLazySystemDLL("ws2_32.dll")

// The shared relay consumes readiness, not blocking reads. Idle Windows sockets
// post a zero-byte overlapped receive to one completion port: no payload buffer
// and no goroutine per socket. Only backpressured writers use WSAPoll.
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
	queryModes  func(winhandle.Owner) (uint32, error)
	immediate   atomic.Uint64
	submitted   atomic.Uint64
	completed   atomic.Uint64
}

type nativeSocketClose struct {
	Sequence uint64         `json:"sequence"`
	Local    netip.AddrPort `json:"local"`
	Handle   uint64         `json:"handle"`
	Error    string         `json:"error,omitempty"`
}

type socketWatch struct {
	mu                       sync.Mutex
	pool                     *readiness
	socket                   winhandle.Owner
	key                      uintptr
	localPort                uint16
	wake                     func()
	op                       windows.Overlapped
	flags                    uint32
	pin                      runtime.Pinner
	pending, detached, write bool
	drained                  chan struct{}
	detachDone               chan struct{}
	detachErr                error
	skipSuccess              bool
	inheritedSkip            bool
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
		policy: policy, cancel: windows.CancelIoEx, queryModes: socketCompletionModes,
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
		if !detached {
			wake()
		}
	}
}

func (p *readiness) stats() map[string]any {
	p.mu.Lock()
	defer p.mu.Unlock()
	ports := make([]uint16, 0, len(p.watches))
	normal, skipped, inherited := 0, 0, 0
	for _, watch := range p.watches {
		ports = append(ports, watch.localPort)
		if watch.skipSuccess {
			skipped++
		} else {
			normal++
		}
		if watch.inheritedSkip {
			inherited++
		}
	}
	closes := make([]nativeSocketClose, 0, min(p.closedCount, uint64(len(p.closes))))
	for i := p.closedCount - uint64(cap(closes)); i < p.closedCount; i++ {
		closes = append(closes, p.closes[i%uint64(len(p.closes))])
	}
	queryError := ""
	if p.policy.err != nil {
		queryError = p.policy.err.Error()
	}
	return map[string]any{
		"sockets": len(p.watches), "ports": ports, "blockedWriters": len(p.writers),
		"completionThread": p.thread.Load(), "closes": closes, "closedCount": p.closedCount,
		"completionPolicy": p.policy.reason, "allowSkipCompletionOnSuccess": p.policy.allowSkip,
		"protocolCatalogEntries": p.policy.entries, "nonIFSProvider": p.policy.nonIFS,
		"providerQueryError": queryError, "normalCompletionSockets": normal,
		"skipSuccessSockets": skipped, "inheritedSkipSuccessSockets": inherited,
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
			rows = append(rows, pollFD{Socket: w.socket.Handle("TCP write poll snapshot"), Events: 0x10}) // POLLWRNORM.
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

func (p *readiness) watch(socket winhandle.Owner, localPort uint16, wake func()) (*socketWatch, error) {
	// Query before association or submission: a duplicate can retain a mode
	// set by Go, and setting only the event flag would not clear skip-success.
	modes, err := p.queryModes(socket)
	if err != nil {
		return nil, err
	}
	inherited := modes&windows.FILE_SKIP_COMPLETION_PORT_ON_SUCCESS != 0
	p.mu.Lock()
	defer p.mu.Unlock()
	p.next++
	w := &socketWatch{pool: p, socket: socket, key: p.next, localPort: localPort, wake: wake,
		skipSuccess: inherited, inheritedSkip: inherited}
	if _, err := windows.CreateIoCompletionPort(socket.Handle("TCP completion attach socket"), p.port.Handle("TCP completion attach port"), w.key, 0); err != nil {
		return nil, err
	}
	if p.policy.allowSkip && !inherited {
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

type readySocket struct {
	mu            sync.Mutex
	blocking      *net.TCPConn
	handle        winhandle.Owner
	goOwner       winhandle.Owner
	pool          *readiness
	watch         *socketWatch
	local, remote net.Addr
	closed        bool
}

func (c *readySocket) Watch(wake func()) (platform.Readiness, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed || c.watch != nil {
		return nil, net.ErrClosed
	}
	var err error
	if c.goOwner.IsZero() {
		c.goOwner, err = ownGoDescriptor(c.blocking, "TCP Go connection before transfer")
		if err != nil {
			return nil, err
		}
	}
	// File performs Go's supported IOCP disassociation before duplication.
	// A second native socket descriptor lets both Go descriptors be released.
	file, err := c.blocking.File()
	if err != nil {
		return nil, err
	}
	fileOwner, err := ownGoDescriptor(file, "TCP File duplicate")
	if err != nil {
		file.Close()
		return nil, err
	}
	defer fileOwner.CloseGo("TCP File duplicate close", file.Close)
	h, err := duplicateForReadiness(file, fileOwner)
	if err != nil {
		return nil, err
	}
	w, err := c.pool.watch(h, uint16(c.local.(*net.TCPAddr).Port), wake)
	if err != nil {
		h.SocketClose("TCP failed readiness registration")
		return nil, err
	}
	c.handle, c.watch = h, w
	c.goOwner.CloseGo("TCP source Go connection close", c.blocking.Close)
	c.blocking = nil
	return w, nil
}

func duplicateForReadiness(file *os.File, source winhandle.Owner) (winhandle.Owner, error) {
	// File's descriptor conversion disassociates Go's IOCP. Its returned
	// integer is not an ownership reference: borrow the descriptor through
	// RawConn while the native duplicate and its nonblocking mode are created.
	file.Fd()
	raw, err := file.SyscallConn()
	if err != nil {
		return winhandle.Owner{}, err
	}
	return duplicateBorrowedSocket(raw, source)
}

func duplicateBorrowedSocket(raw syscall.RawConn, source winhandle.Owner) (winhandle.Owner, error) {
	var duplicate winhandle.Owner
	var nativeError error
	borrowError := raw.Control(func(descriptor uintptr) {
		if windows.Handle(descriptor) != source.GoBorrow("WSADuplicateSocket source borrow") {
			panic("Go descriptor changed inside its ownership borrow")
		}
		var protocol windows.WSAProtocolInfo
		nativeError = windows.WSADuplicateSocket(windows.Handle(descriptor), uint32(os.Getpid()), &protocol)
		if nativeError != nil {
			return
		}
		var h windows.Handle
		h, nativeError = windows.WSASocket(-1, -1, -1, &protocol, 0, windows.WSA_FLAG_OVERLAPPED|windows.WSA_FLAG_NO_HANDLE_INHERIT)
		if nativeError != nil {
			return
		}
		duplicate = winhandle.Open(h, "WSASocket native duplicate")
		var nonblocking uint32 = 1
		code, _, failure := winsock.NewProc("ioctlsocket").Call(uintptr(duplicate.Handle("native duplicate nonblocking")), 0x8004667e, uintptr(unsafe.Pointer(&nonblocking)))
		if int32(code) != 0 {
			nativeError = failure
			duplicate.SocketClose("native duplicate nonblocking failure")
			duplicate = winhandle.Owner{}
		}
	})
	if err := errors.Join(borrowError, nativeError); err != nil {
		return winhandle.Owner{}, err
	}
	return duplicate, nil
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
	if c.closed || c.watch == nil {
		return 0, net.ErrClosed
	}
	return socketIOFlags(c.handle, "recv", b, flags)
}
func (c *readySocket) TryWrite(b []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed || c.watch == nil {
		return 0, net.ErrClosed
	}
	return socketIO(c.handle, "send", b)
}
func (c *readySocket) Read(b []byte) (int, error) {
	c.mu.Lock()
	conn := c.blocking
	c.mu.Unlock()
	if conn == nil {
		return 0, errors.New("socket I/O transferred to relay")
	}
	return conn.Read(b)
}
func (c *readySocket) Write(b []byte) (int, error) {
	c.mu.Lock()
	conn := c.blocking
	c.mu.Unlock()
	if conn == nil {
		return 0, errors.New("socket I/O transferred to relay")
	}
	return conn.Write(b)
}
func (c *readySocket) LocalAddr() net.Addr  { return c.local }
func (c *readySocket) RemoteAddr() net.Addr { return c.remote }
func (c *readySocket) SetDeadline(t time.Time) error {
	c.mu.Lock()
	conn := c.blocking
	c.mu.Unlock()
	if conn == nil {
		return errors.New("deadline after readiness transfer")
	}
	return conn.SetDeadline(t)
}
func (c *readySocket) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	conn := c.blocking
	c.mu.Unlock()
	if conn == nil {
		return errors.New("deadline after readiness transfer")
	}
	return conn.SetReadDeadline(t)
}
func (c *readySocket) SetWriteDeadline(t time.Time) error {
	c.mu.Lock()
	conn := c.blocking
	c.mu.Unlock()
	if conn == nil {
		return errors.New("deadline after readiness transfer")
	}
	return conn.SetWriteDeadline(t)
}
func (c *readySocket) SetLinger(seconds int) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return net.ErrClosed
	}
	if c.blocking != nil {
		return c.blocking.SetLinger(seconds)
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
	if c.blocking != nil {
		if how == windows.SHUT_RD {
			return c.blocking.CloseRead()
		}
		return c.blocking.CloseWrite()
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
	if c.blocking != nil {
		if c.goOwner.IsZero() {
			var err error
			c.goOwner, err = ownGoDescriptor(c.blocking, "TCP Go connection before close")
			if err != nil {
				return err
			}
		}
		return c.goOwner.CloseGo("TCP Go connection close", c.blocking.Close)
	}
	c.watch.Detach()
	h := c.handle.Handle("TCP final close ownership")
	err := c.handle.SocketClose("TCP native socket close")
	c.pool.recordClose(c.local.(*net.TCPAddr).AddrPort(), h, err)
	return err
}

// Used by probes before readiness transfer as well as the shared relay.
var _ platform.ReadyTCP = (*readySocket)(nil)
