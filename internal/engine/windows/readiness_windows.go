//go:build windows

package winengine

import (
	"errors"
	"io"
	"net"
	"os"
	"runtime"
	"sync"
	"time"
	"unsafe"

	"github.com/AyoubAchour/net-switch/internal/engine/platform"
	"github.com/AyoubAchour/net-switch/internal/winclock"
	"golang.org/x/sys/windows"
)

var winsock = windows.NewLazySystemDLL("ws2_32.dll")

// The shared relay consumes readiness, not blocking reads. Idle Windows sockets
// post a zero-byte overlapped receive to one completion port: no payload buffer
// and no goroutine per socket. Only backpressured writers use WSAPoll.
type readiness struct {
	mu      sync.Mutex
	port    windows.Handle
	next    uintptr
	watches map[uintptr]*socketWatch
	writers map[uintptr]*socketWatch
	stop    chan struct{}
	wg      sync.WaitGroup
}

type socketWatch struct {
	mu                       sync.Mutex
	pool                     *readiness
	socket                   windows.Handle
	key                      uintptr
	wake                     func()
	op                       windows.Overlapped
	flags                    uint32
	pin                      runtime.Pinner
	pending, detached, write bool
	drained                  chan struct{}
}

func newReadiness() (*readiness, error) {
	port, err := windows.CreateIoCompletionPort(windows.InvalidHandle, 0, 0, 1)
	if err != nil {
		return nil, err
	}
	p := &readiness{port: port, watches: map[uintptr]*socketWatch{}, writers: map[uintptr]*socketWatch{}, stop: make(chan struct{})}
	p.wg.Go(p.completions)
	p.wg.Go(p.pollWrites)
	return p, nil
}

func (p *readiness) completions() {
	for {
		var count uint32
		var key uintptr
		var op *windows.Overlapped
		err := windows.GetQueuedCompletionStatus(p.port, &count, &key, &op, windows.INFINITE)
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

type pollFD struct {
	Socket           windows.Handle
	Events, Returned int16
}

func (p *readiness) pollWrites() {
	var rows []pollFD
	var watches []*socketWatch
	for {
		if !winclock.System.WaitDone(p.stop, 2*time.Millisecond) {
			return
		}
		rows, watches = rows[:0], watches[:0]
		p.mu.Lock()
		for _, w := range p.writers {
			rows = append(rows, pollFD{Socket: w.socket, Events: 0x10}) // POLLWRNORM.
			watches = append(watches, w)
		}
		p.mu.Unlock()
		if len(rows) == 0 {
			continue
		}
		n, _, _ := winsock.NewProc("WSAPoll").Call(uintptr(unsafe.Pointer(&rows[0])), uintptr(len(rows)), 0)
		if int32(n) <= 0 {
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

func (p *readiness) watch(socket windows.Handle, wake func()) (*socketWatch, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.next++
	w := &socketWatch{pool: p, socket: socket, key: p.next, wake: wake}
	if _, err := windows.CreateIoCompletionPort(socket, p.port, w.key, 0); err != nil {
		return nil, err
	}
	// Go's socket may already have these modes. Setting them explicitly gives
	// inline success one unambiguous owner; no completion is then expected.
	if err := windows.SetFileCompletionNotificationModes(socket, 1|2); err != nil {
		return nil, err
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
	err := windows.WSARecv(w.socket, &buf, 1, nil, &w.flags, &w.op, nil)
	if errors.Is(err, windows.ERROR_IO_PENDING) {
		w.mu.Unlock()
		return nil
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
		w.mu.Unlock()
		return
	}
	w.detached = true
	w.pool.mu.Lock()
	delete(w.pool.writers, w.key)
	w.pool.mu.Unlock()
	var drained chan struct{}
	if w.pending {
		drained = make(chan struct{})
		w.drained = drained
		windows.CancelIoEx(w.socket, &w.op)
	}
	w.mu.Unlock()
	if drained != nil {
		<-drained
	}
	w.pool.mu.Lock()
	delete(w.pool.watches, w.key)
	w.pool.mu.Unlock()
	w.pin.Unpin()
}

func (p *readiness) close() error {
	p.mu.Lock()
	n := len(p.watches)
	p.mu.Unlock()
	if n != 0 {
		return errors.New("cannot close readiness with live sockets")
	}
	close(p.stop)
	windows.PostQueuedCompletionStatus(p.port, 0, 0, nil)
	p.wg.Wait()
	return windows.CloseHandle(p.port)
}

type readySocket struct {
	mu            sync.Mutex
	blocking      *net.TCPConn
	handle        windows.Handle
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
	// File performs Go's supported IOCP disassociation before duplication.
	// A second native socket descriptor lets both Go descriptors be released.
	file, err := c.blocking.File()
	if err != nil {
		return nil, err
	}
	defer file.Close()
	var info windows.WSAProtocolInfo
	if err := windows.WSADuplicateSocket(windows.Handle(file.Fd()), uint32(os.Getpid()), &info); err != nil {
		return nil, err
	}
	h, err := windows.WSASocket(-1, -1, -1, &info, 0, windows.WSA_FLAG_OVERLAPPED|windows.WSA_FLAG_NO_HANDLE_INHERIT)
	if err != nil {
		return nil, err
	}
	var nonblocking uint32 = 1
	code, _, callErr := winsock.NewProc("ioctlsocket").Call(uintptr(h), 0x8004667e, uintptr(unsafe.Pointer(&nonblocking)))
	if int32(code) != 0 {
		windows.Closesocket(h)
		return nil, callErr
	}
	w, err := c.pool.watch(h, wake)
	if err != nil {
		windows.Closesocket(h)
		return nil, err
	}
	c.handle, c.watch = h, w
	c.blocking.Close()
	c.blocking = nil
	return w, nil
}

func socketIO(h windows.Handle, name string, b []byte) (int, error) {
	if len(b) == 0 {
		return 0, nil
	}
	n, _, err := winsock.NewProc(name).Call(uintptr(h), uintptr(unsafe.Pointer(&b[0])), uintptr(len(b)), 0)
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
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed || c.watch == nil {
		return 0, net.ErrClosed
	}
	return socketIO(c.handle, "recv", b)
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
	return windows.SetsockoptLinger(c.handle, windows.SOL_SOCKET, windows.SO_LINGER, &linger)
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
	return windows.Shutdown(c.handle, how)
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
		return c.blocking.Close()
	}
	c.watch.Detach()
	return windows.Closesocket(c.handle)
}

// Used by probes before readiness transfer as well as the shared relay.
var _ platform.ReadyTCP = (*readySocket)(nil)
