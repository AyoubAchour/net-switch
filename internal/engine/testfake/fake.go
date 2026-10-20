// Package testfake provides in-memory platform implementations for core tests.
package testfake

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/AyoubAchour/net-switch/internal/engine/flowapi"
	"github.com/AyoubAchour/net-switch/internal/engine/platform"
)

type Owners struct {
	Value platform.Owner
	Err   error
	Gate  <-chan struct{}
}

func (o *Owners) get(ctx context.Context) (platform.Owner, error) {
	if o.Gate != nil {
		select {
		case <-o.Gate:
		case <-ctx.Done():
			return platform.Owner{}, ctx.Err()
		}
	}
	return o.Value, o.Err
}
func (o *Owners) TCP(ctx context.Context, _ platform.Tuple) (platform.Owner, error) {
	return o.get(ctx)
}
func (o *Owners) UDP(ctx context.Context, _ netip.AddrPort) (platform.Owner, error) {
	return o.get(ctx)
}

type Controller struct {
	Err                               error
	ResolveErr                        error
	Line                              string
	Begun, Closed, Resolved, Up, Down atomic.Uint64
	Pending                           atomic.Int64
	Limit                             int64
}

func (c *Controller) Begin(_ string, _ platform.Tuple) (flowapi.Ticket, error) {
	if c.Err != nil {
		return nil, c.Err
	}
	c.Begun.Add(1)
	return &Ticket{c: c}, nil
}
func (c *Controller) AllowReject(string) bool { return true }
func (c *Controller) ReservePending(n int) bool {
	for {
		old := c.Pending.Load()
		if c.Limit > 0 && old+int64(n) > c.Limit {
			return false
		}
		if c.Pending.CompareAndSwap(old, old+int64(n)) {
			return true
		}
	}
}
func (c *Controller) ReleasePending(n int) { c.Pending.Add(-int64(n)) }

type Ticket struct {
	c    *Controller
	once sync.Once
}

func (t *Ticket) Resolve(platform.Owner) (flowapi.Decision, error) {
	if t.c.ResolveErr != nil {
		return flowapi.Decision{}, t.c.ResolveErr
	}
	t.c.Resolved.Add(1)
	return flowapi.Decision{Line: t.c.Line, Lane: t.c.Line, Revision: 1}, nil
}
func (*Ticket) Buffers() (int, int)          { return 64 << 10, 64 << 10 }
func (*Ticket) Established(netip.Addr)       {}
func (t *Ticket) Add(up, down uint64)        { t.c.Up.Add(up); t.c.Down.Add(down) }
func (*Ticket) SetCancel(context.CancelFunc) {}
func (*Ticket) TimeWait() bool               { return true }
func (*Ticket) Closing() bool                { return true }
func (*Ticket) EndTimeWait()                 {}
func (*Ticket) Retire()                      {}
func (t *Ticket) Close()                     { t.once.Do(func() { t.c.Closed.Add(1) }) }

type Conn struct {
	r     *io.PipeReader
	w     *io.PipeWriter
	reset atomic.Bool
}

func Pair() (*Conn, *Conn) {
	ar, aw := io.Pipe()
	br, bw := io.Pipe()
	return &Conn{r: ar, w: bw}, &Conn{r: br, w: aw}
}
func (c *Conn) Read(p []byte) (int, error)  { return c.r.Read(p) }
func (c *Conn) Write(p []byte) (int, error) { return c.w.Write(p) }
func (c *Conn) Close() error {
	if c.reset.Load() {
		c.Abort(errors.New("connection reset"))
		return nil
	}
	c.r.Close()
	return c.w.Close()
}
func (c *Conn) SetLinger(n int) error { c.reset.Store(n == 0); return nil }
func (c *Conn) Abort(err error)       { c.r.CloseWithError(err); c.w.CloseWithError(err) }
func (c *Conn) CloseRead() error      { return c.r.Close() }
func (c *Conn) CloseWrite() error     { return c.w.Close() }
func (*Conn) LocalAddr() net.Addr {
	return net.TCPAddrFromAddrPort(netip.MustParseAddrPort("192.0.2.1:5000"))
}
func (*Conn) RemoteAddr() net.Addr {
	return net.TCPAddrFromAddrPort(netip.MustParseAddrPort("203.0.113.7:443"))
}
func (*Conn) SetDeadline(time.Time) error      { return nil }
func (*Conn) SetReadDeadline(time.Time) error  { return nil }
func (*Conn) SetWriteDeadline(time.Time) error { return nil }

type Dialer struct {
	TCPFunc func(context.Context, string, netip.AddrPort) (platform.TCPConn, error)
	UDPFunc func(context.Context, string, bool) (platform.UDPConn, error)
}

func (d Dialer) DialTCP(c context.Context, l string, a netip.AddrPort) (platform.TCPConn, error) {
	if d.TCPFunc == nil {
		return nil, errors.New("unexpected TCP dial")
	}
	return d.TCPFunc(c, l, a)
}
func (d Dialer) OpenUDP(c context.Context, l string, v6 bool) (platform.UDPConn, error) {
	if d.UDPFunc == nil {
		return nil, errors.New("unexpected UDP open")
	}
	return d.UDPFunc(c, l, v6)
}

type Output struct{ Packets chan []byte }

func (o Output) Send(b []byte) bool {
	select {
	case o.Packets <- append([]byte(nil), b...):
		return true
	default:
		return false
	}
}

type Tun struct {
	In, Out chan []byte
	Done    chan struct{}
	once    sync.Once
}

func NewTun() *Tun {
	return &Tun{In: make(chan []byte, 1024), Out: make(chan []byte, 1024), Done: make(chan struct{})}
}
func (t *Tun) ReadPacket(ctx context.Context, b []byte) (int, error) {
	select {
	case p := <-t.In:
		if len(p) > len(b) {
			return 0, io.ErrShortBuffer
		}
		return copy(b, p), nil
	case <-ctx.Done():
		return 0, ctx.Err()
	case <-t.Done:
		return 0, io.EOF
	}
}
func (t *Tun) WritePacket(ctx context.Context, b []byte) error {
	select {
	case t.Out <- append([]byte(nil), b...):
		return nil
	case <-ctx.Done():
		return ctx.Err()
	case <-t.Done:
		return io.ErrClosedPipe
	}
}
func (*Tun) MTU() int       { return 9000 }
func (t *Tun) Close() error { t.once.Do(func() { close(t.Done) }); return nil }

type Routes struct {
	mu    sync.Mutex
	Calls []string
	Fail  string
}

func (r *Routes) call(s string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.Calls = append(r.Calls, s)
	if r.Fail == s {
		return errors.New(s)
	}
	return nil
}
func (r *Routes) Prepare(context.Context, []platform.Line) error { return r.call("prepare") }
func (r *Routes) Capture(context.Context) error                  { return r.call("capture") }
func (r *Routes) Cleanup(context.Context) error                  { return r.call("cleanup") }
