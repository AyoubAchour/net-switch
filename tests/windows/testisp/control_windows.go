//go:build windows

package main

import (
	"log"
	"net"
	"sync/atomic"
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
	started    time.Time
	deadline   atomic.Int64
	readBytes  atomic.Uint64
	writeBytes atomic.Uint64
}

func (c *controlConn) CloseWrite() error {
	return c.Conn.(*net.TCPConn).CloseWrite()
}

func (c *controlConn) SetReadDeadline(deadline time.Time) error {
	c.deadline.Store(deadline.UnixMilli())
	return c.Conn.SetReadDeadline(deadline)
}

func (c *controlConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	c.readBytes.Add(uint64(n))
	if err != nil {
		log.Printf("control read peer=%s age=%s deadline=%s bytes=%d error=%v", c.RemoteAddr(), time.Since(c.started), time.UnixMilli(c.deadline.Load()).UTC().Format(time.RFC3339Nano), n, err)
	}
	return n, err
}

func (c *controlConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	c.writeBytes.Add(uint64(n))
	if err != nil {
		log.Printf("control write peer=%s age=%s bytes=%d error=%v", c.RemoteAddr(), time.Since(c.started), n, err)
	}
	return n, err
}

func (c *controlConn) Close() error {
	log.Printf("control close peer=%s age=%s read=%d written=%d", c.RemoteAddr(), time.Since(c.started), c.readBytes.Load(), c.writeBytes.Load())
	return c.Conn.Close()
}
