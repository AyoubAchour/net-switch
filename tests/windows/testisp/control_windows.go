//go:build windows

package main

import (
	"log"
	"net"
	"time"
)

// Observe the loopback control socket separately from the TUN data path.
// Never log HTTP bytes: they contain the control token.
type controlListener struct{ net.Listener }

func (l controlListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	log.Printf("control accept peer=%s", c.RemoteAddr())
	return &controlConn{Conn: c, started: time.Now()}, nil
}

type controlConn struct {
	net.Conn
	started time.Time
}

func (c *controlConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if err != nil {
		log.Printf("control read peer=%s age=%s bytes=%d error=%v", c.RemoteAddr(), time.Since(c.started), n, err)
	}
	return n, err
}

func (c *controlConn) Close() error {
	log.Printf("control close peer=%s age=%s", c.RemoteAddr(), time.Since(c.started))
	return c.Conn.Close()
}
