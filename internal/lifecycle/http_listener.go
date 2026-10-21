package lifecycle

import (
	"context"
	"errors"
	"net"
	"sync"
	"time"

	"github.com/AyoubAchour/net-switch/internal/localipc"
)

type httpPeerKey struct{}

type admittedHTTPConn struct {
	net.Conn
	user   string
	limits *connectionLimits
	once   sync.Once
}

func (c *admittedHTTPConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(func() { c.limits.release(c.user) })
	return err
}

// Connections accepted but not yet resolved or handed to the HTTP server.
const httpAdmissionQueue = 256

type queuedHTTPConn struct {
	conn     net.Conn
	accepted time.Time
}

// httpListener admits loopback HTTP connections by their OS identity. The
// raw accept loop never waits for that identity. A separate resolver takes
// every connection queued since its previous pass and resolves the batch in
// one lookup (one machine-wide TCP table snapshot on Windows). Connection
// churn or a large table from other users then costs one lookup per batch,
// so the owner's connection waits for at most one batch, not for every
// connection accepted before it.
type httpListener struct {
	net.Listener
	limits   *connectionLimits
	log      func(string)
	resolve  func([]localipc.TCPTuple) []localipc.TCPIdentity
	rejected rejectionLog
	overflow rejectionLog

	mu        sync.Mutex
	queue     []queuedHTTPConn
	drained   bool
	wake      chan struct{}
	ready     chan *admittedHTTPConn
	done      chan struct{}
	failed    chan struct{}
	err       error
	closeOnce sync.Once
	failOnce  sync.Once
}

func newHTTPListener(l net.Listener, limits *connectionLimits, log func(string), resolve func([]localipc.TCPTuple) []localipc.TCPIdentity) *httpListener {
	if resolve == nil {
		resolve = localipc.TCPOwners
	}
	h := &httpListener{
		Listener: l, limits: limits, log: log, resolve: resolve,
		wake:   make(chan struct{}, 1),
		ready:  make(chan *admittedHTTPConn, httpAdmissionQueue),
		done:   make(chan struct{}),
		failed: make(chan struct{}),
	}
	go h.acceptRaw()
	go h.admit()
	return h
}

func (l *httpListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.ready:
		return c, nil
	case <-l.failed:
		// Hand over anything admitted before the failure first.
		select {
		case c := <-l.ready:
			return c, nil
		default:
		}
		return nil, l.err
	}
}

func (l *httpListener) Close() error {
	var err error
	l.closeOnce.Do(func() {
		close(l.done)
		err = l.Listener.Close()
	})
	return err
}

func (l *httpListener) fail(err error) {
	l.failOnce.Do(func() {
		l.err = err
		close(l.failed)
	})
}

func (l *httpListener) acceptRaw() {
	var delay time.Duration
	for {
		conn, err := l.Listener.Accept()
		if err != nil {
			// Match net/http: back off on temporary errors such as running
			// out of file descriptors, and stop on anything else.
			var temporary interface{ Temporary() bool }
			if errors.As(err, &temporary) && temporary.Temporary() {
				delay = min(max(2*delay, 5*time.Millisecond), time.Second)
				select {
				case <-time.After(delay):
					continue
				case <-l.done:
				}
			}
			l.fail(err)
			return
		}
		delay = 0
		l.mu.Lock()
		if l.drained {
			l.mu.Unlock()
			conn.Close()
			continue
		}
		if len(l.queue) >= httpAdmissionQueue {
			l.mu.Unlock()
			conn.Close()
			l.overflow.report(l.log, "HTTP admission queue full; connection refused")
			continue
		}
		l.queue = append(l.queue, queuedHTTPConn{conn, time.Now()})
		l.mu.Unlock()
		select {
		case l.wake <- struct{}{}:
		default:
		}
	}
}

func (l *httpListener) admit() {
	defer l.drain()
	for {
		select {
		case <-l.wake:
		case <-l.done:
			return
		}
		l.mu.Lock()
		batch := l.queue
		l.queue = nil
		l.mu.Unlock()
		tuples := make([]localipc.TCPTuple, len(batch))
		for i, q := range batch {
			client, _ := q.conn.RemoteAddr().(*net.TCPAddr)
			server, _ := q.conn.LocalAddr().(*net.TCPAddr)
			tuples[i] = localipc.TCPTuple{Client: client, Server: server, Accepted: q.accepted}
		}
		identities := l.resolve(tuples)
		for i, q := range batch {
			user := "unresolved"
			if i < len(identities) && identities[i].Err == nil && identities[i].User != "" {
				user = identities[i].User
			}
			if !l.limits.take(user) {
				q.conn.Close()
				l.rejected.report(l.log, "HTTP connection limit reached; owner slots remain reserved")
				continue
			}
			admitted := &admittedHTTPConn{Conn: q.conn, user: user, limits: l.limits}
			select {
			case l.ready <- admitted:
			case <-l.done:
				admitted.Close()
			}
		}
	}
}

// drain closes everything that was accepted but never reached the server.
func (l *httpListener) drain() {
	l.mu.Lock()
	batch := l.queue
	l.queue = nil
	l.drained = true
	l.mu.Unlock()
	for _, q := range batch {
		q.conn.Close()
	}
	for {
		select {
		case c := <-l.ready:
			c.Close()
		default:
			return
		}
	}
}

func httpPeerContext(ctx context.Context, c net.Conn) context.Context {
	if admitted, ok := c.(*admittedHTTPConn); ok {
		return context.WithValue(ctx, httpPeerKey{}, admitted.user)
	}
	return ctx
}
