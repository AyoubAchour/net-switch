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
const httpAdmissionQueue = 1024

// httpLookupInterval is the usual gap between identity lookups. Under
// connection churn, connections gather into larger batches instead of each
// costing a machine-wide table snapshot. The gap is cut short once
// httpLookupBatch connections wait, so a fast churn cannot fill the queue
// and push the owner out: lookups then run back to back, each serving at
// least that many connections. Either way another user's churn costs at
// most twenty snapshots a second or one per httpLookupBatch connections.
const (
	httpLookupInterval = 50 * time.Millisecond
	httpLookupBatch    = 128
)

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
	interval time.Duration
	rejected rejectionLog
	overflow rejectionLog

	mu        sync.Mutex
	queue     []net.Conn
	drained   bool
	wake      chan struct{}
	full      chan struct{}
	ready     chan *admittedHTTPConn
	done      chan struct{}
	failed    chan struct{}
	err       error
	closeOnce sync.Once
	failOnce  sync.Once
}

func newHTTPListener(l net.Listener, limits *connectionLimits, log func(string), resolve func([]localipc.TCPTuple) []localipc.TCPIdentity) *httpListener {
	return newHTTPListenerEvery(l, limits, log, resolve, httpLookupInterval)
}

func newHTTPListenerEvery(l net.Listener, limits *connectionLimits, log func(string), resolve func([]localipc.TCPTuple) []localipc.TCPIdentity, interval time.Duration) *httpListener {
	if resolve == nil {
		resolve = localipc.TCPOwners
	}
	h := &httpListener{
		Listener: l, limits: limits, log: log, resolve: resolve, interval: interval,
		wake:   make(chan struct{}, 1),
		full:   make(chan struct{}, 1),
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
		l.queue = append(l.queue, conn)
		batch := len(l.queue) >= httpLookupBatch
		l.mu.Unlock()
		select {
		case l.wake <- struct{}{}:
		default:
		}
		if batch {
			select {
			case l.full <- struct{}{}:
			default:
			}
		}
	}
}

func (l *httpListener) admit() {
	defer l.drain()
	var last time.Time
	for {
		select {
		case <-l.wake:
		case <-l.done:
			return
		}
		if wait := l.interval - time.Since(last); wait > 0 {
			timer := time.NewTimer(wait)
			select {
			case <-timer.C:
			case <-l.full:
			case <-l.done:
				timer.Stop()
				return
			}
			timer.Stop()
		}
		last = time.Now()
		l.mu.Lock()
		batch := l.queue
		l.queue = nil
		l.mu.Unlock()
		tuples := make([]localipc.TCPTuple, len(batch))
		for i, conn := range batch {
			client, _ := conn.RemoteAddr().(*net.TCPAddr)
			server, _ := conn.LocalAddr().(*net.TCPAddr)
			tuples[i] = localipc.TCPTuple{Client: client, Server: server}
		}
		identities := l.resolve(tuples)
		for i, conn := range batch {
			user := "unresolved"
			if i < len(identities) && identities[i].Err == nil && identities[i].User != "" {
				user = identities[i].User
			}
			if !l.limits.take(user) {
				conn.Close()
				l.rejected.report(l.log, "HTTP connection limit reached; owner slots remain reserved")
				continue
			}
			admitted := &admittedHTTPConn{Conn: conn, user: user, limits: l.limits}
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
	for _, conn := range batch {
		conn.Close()
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
