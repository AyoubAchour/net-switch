package lifecycle

import (
	"context"
	"net"
	"sync"

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

type httpListener struct {
	net.Listener
	limits     *connectionLimits
	log        func(string)
	rejections rejectionLog
}

func (l *httpListener) Accept() (net.Conn, error) {
	for {
		conn, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		client, cok := conn.RemoteAddr().(*net.TCPAddr)
		server, sok := conn.LocalAddr().(*net.TCPAddr)
		user := "unresolved"
		if cok && sok {
			if identity, err := localipc.TCPOwner(client, server); err == nil {
				user = identity
			}
		}
		if !l.limits.take(user) {
			conn.Close()
			l.rejections.report(l.log, "HTTP connection limit reached; owner slots remain reserved")
			continue
		}
		return &admittedHTTPConn{Conn: conn, user: user, limits: l.limits}, nil
	}
}

func httpPeerContext(ctx context.Context, c net.Conn) context.Context {
	if admitted, ok := c.(*admittedHTTPConn); ok {
		return context.WithValue(ctx, httpPeerKey{}, admitted.user)
	}
	return ctx
}
