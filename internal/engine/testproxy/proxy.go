//go:build lifecycle_test || acceptance

package testproxy

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/AyoubAchour/net-switch/internal/engine/flowapi"
	"github.com/AyoubAchour/net-switch/internal/engine/platform"
)

const Enabled = true
const MaxConnections = 64
const HeaderBytes = 8192

type Server struct {
	o       Options
	l       net.Listener
	ctx     context.Context
	cancel  context.CancelFunc
	mu      sync.Mutex
	clients map[net.Conn]struct{}
	wg      sync.WaitGroup
	done    chan struct{}
	once    sync.Once
}

func New(ctx context.Context, o Options) (*Server, error) {
	address, err := netip.ParseAddrPort(o.Address)
	if err != nil || !address.Addr().IsLoopback() || address.Addr().Zone() != "" {
		return nil, errors.New("test proxy requires a literal loopback address")
	}
	if o.Table == nil || o.Owners == nil || o.Dial == nil {
		return nil, errors.New("test proxy dependencies missing")
	}
	if o.Listen == nil {
		o.Listen = net.Listen
	}
	l, err := o.Listen("tcp", address.String())
	if err != nil {
		return nil, err
	}
	run, cancel := context.WithCancel(ctx)
	s := &Server{o: o, l: l, ctx: run, cancel: cancel, clients: map[net.Conn]struct{}{}, done: make(chan struct{})}
	go s.accept()
	return s, nil
}

func (s *Server) Status() Status {
	s.mu.Lock()
	defer s.mu.Unlock()
	return Status{Address: s.l.Addr().String(), Connections: len(s.clients)}
}

func (s *Server) accept() {
	defer close(s.done)
	stop := context.AfterFunc(s.ctx, func() { s.l.Close() })
	defer stop()
	for {
		c, err := s.l.Accept()
		if err != nil {
			return
		}
		peer, err := netip.ParseAddrPort(c.RemoteAddr().String())
		s.mu.Lock()
		if err != nil || !peer.Addr().IsLoopback() || s.ctx.Err() != nil || len(s.clients) >= MaxConnections {
			s.mu.Unlock()
			c.Close()
			continue
		}
		s.clients[c] = struct{}{}
		s.wg.Add(1)
		s.mu.Unlock()
		go func() {
			defer s.wg.Done()
			defer func() { c.Close(); s.mu.Lock(); delete(s.clients, c); s.mu.Unlock() }()
			s.serve(c)
		}()
	}
}

func (s *Server) Close() error {
	s.once.Do(func() { s.cancel(); s.l.Close() })
	<-s.done // no more Add calls before Wait
	s.mu.Lock()
	for c := range s.clients {
		c.Close()
	}
	s.mu.Unlock()
	s.wg.Wait()
	return nil
}

func (s *Server) serve(c net.Conn) {
	ctx, cancel := context.WithCancel(s.ctx)
	defer cancel()
	stopClient := context.AfterFunc(ctx, func() { c.Close() })
	defer stopClient()
	c.SetDeadline(time.Now().Add(5 * time.Second))
	reader := bufio.NewReaderSize(c, 4096)
	first, err := reader.Peek(1)
	if err != nil {
		return
	}
	socks := first[0] == 5
	target, err := handshake(c, reader, socks)
	if err != nil {
		return
	}
	reply := func(ok, denied bool, address net.Addr) error {
		if socks {
			return socksReply(c, ok, denied, address)
		}
		status := "200 Connection Established"
		if !ok {
			status = "502 Bad Gateway"
			if denied {
				status = "403 Forbidden"
			}
		}
		_, err := fmt.Fprintf(c, "HTTP/1.1 %s\r\n\r\n", status)
		return err
	}
	setup, stopSetup := context.WithTimeout(ctx, 10*time.Second)
	defer stopSetup()
	deadline, _ := setup.Deadline()
	c.SetDeadline(deadline)
	dst, err := destination(setup, target)
	if err != nil {
		reply(false, false, nil)
		return
	}
	peer, _ := netip.ParseAddrPort(c.RemoteAddr().String())
	local, _ := netip.ParseAddrPort(c.LocalAddr().String())
	ticket, err := s.o.Table.Begin("tcp", platform.Tuple{Source: peer, Destination: dst})
	if err != nil {
		reply(false, true, nil)
		return
	}
	defer ticket.Close()
	ticket.SetCancel(cancel)
	bound := 50 * time.Millisecond
	if owner, ok := s.o.Owners.(interface{ TCPLookupBound() time.Duration }); ok {
		bound = owner.TCPLookupBound()
	}
	lookup, stopLookup := context.WithTimeout(setup, bound)
	started := time.Now()
	owner, lookupErr := s.o.Owners.TCP(lookup, platform.Tuple{Source: peer, Destination: local})
	stopLookup()
	s.o.Table.Lookup(time.Since(started), lookupErr, owner)
	if lookupErr != nil {
		owner = platform.Owner{}
	}
	decision, err := ticket.Resolve(owner)
	if err != nil {
		reply(false, true, nil)
		return
	}
	out, err := s.o.Dial(setup, decision.Line, dst)
	if err != nil {
		reply(false, false, nil)
		return
	}
	defer out.Close()
	stopOut := context.AfterFunc(ctx, func() { out.Close() })
	defer stopOut()
	source, _ := netip.ParseAddrPort(out.LocalAddr().String())
	ticket.Established(source.Addr())
	if err := reply(true, false, out.LocalAddr()); err != nil {
		return
	}
	// At most two 16 KiB relay buffers per reserved session (2 MiB total).
	// No buffers/goroutines survive shutdown or a two-minute test connection.
	deadline = time.Now().Add(2 * time.Minute)
	c.SetDeadline(deadline)
	out.SetDeadline(deadline)
	upDone := make(chan struct{})
	go func() { relay(out, reader, ticket, true); halfClose(out); close(upDone) }()
	relay(c, out, ticket, false)
	halfClose(c)
	<-upDone
}

func halfClose(c net.Conn) {
	if h, ok := c.(interface{ CloseWrite() error }); ok {
		h.CloseWrite()
	} else {
		c.Close()
	}
}

func relay(dst io.Writer, src io.Reader, ticket flowapi.Ticket, up bool) {
	b := make([]byte, 16<<10)
	for {
		n, readErr := src.Read(b)
		if n != 0 {
			written, err := dst.Write(b[:n])
			if up {
				ticket.Add(uint64(written), 0)
			} else {
				ticket.Add(0, uint64(written))
			}
			if err != nil || written != n {
				return
			}
		}
		if readErr != nil {
			return
		}
	}
}

func handshake(c net.Conn, r *bufio.Reader, socks bool) (string, error) {
	if !socks {
		var header []byte
		for len(header) <= HeaderBytes {
			line, err := r.ReadSlice('\n')
			if err != nil {
				return "", err
			}
			header = append(header, line...)
			if len(header) > HeaderBytes {
				break
			}
			if bytes.Equal(line, []byte("\r\n")) {
				req, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(header)))
				if err != nil {
					return "", err
				}
				defer req.Body.Close()
				if req.Method != http.MethodConnect || req.ContentLength > 0 || len(req.TransferEncoding) != 0 {
					return "", errors.New("only bodyless CONNECT is supported")
				}
				return req.RequestURI, nil
			}
		}
		return "", errors.New("CONNECT headers exceed limit")
	}
	var greeting [2]byte
	if _, err := io.ReadFull(r, greeting[:]); err != nil {
		return "", err
	}
	methods := make([]byte, int(greeting[1]))
	if _, err := io.ReadFull(r, methods); err != nil {
		return "", err
	}
	if !bytes.Contains(methods, []byte{0}) {
		c.Write([]byte{5, 255})
		return "", errors.New("SOCKS no-auth method required")
	}
	if _, err := c.Write([]byte{5, 0}); err != nil {
		return "", err
	}
	var command [4]byte
	if _, err := io.ReadFull(r, command[:]); err != nil {
		return "", err
	}
	if command[0] != 5 || command[1] != 1 || command[2] != 0 {
		c.Write([]byte{5, 7, 0, 1, 0, 0, 0, 0, 0, 0})
		return "", errors.New("SOCKS TCP CONNECT required")
	}
	var host string
	switch command[3] {
	case 1, 4:
		size := 4
		if command[3] == 4 {
			size = 16
		}
		b := make([]byte, size)
		if _, err := io.ReadFull(r, b); err != nil {
			return "", err
		}
		ip, _ := netip.AddrFromSlice(b)
		host = ip.String()
	case 3:
		n, err := r.ReadByte()
		if err != nil {
			return "", err
		}
		b := make([]byte, int(n))
		if _, err := io.ReadFull(r, b); err != nil {
			return "", err
		}
		host = string(b)
	default:
		c.Write([]byte{5, 8, 0, 1, 0, 0, 0, 0, 0, 0})
		return "", errors.New("unsupported SOCKS address type")
	}
	var port [2]byte
	if _, err := io.ReadFull(r, port[:]); err != nil {
		return "", err
	}
	return net.JoinHostPort(host, strconv.Itoa(int(binary.BigEndian.Uint16(port[:])))), nil
}

func destination(ctx context.Context, target string) (netip.AddrPort, error) {
	host, service, err := net.SplitHostPort(target)
	if err != nil || host == "" || len(host) > 253 || strings.ContainsAny(host, "\x00\r\n\t /@%") {
		return netip.AddrPort{}, errors.New("invalid proxy target")
	}
	port, err := strconv.ParseUint(service, 10, 16)
	if err != nil || port == 0 {
		return netip.AddrPort{}, errors.New("invalid proxy port")
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
		if err != nil || len(ips) == 0 {
			return netip.AddrPort{}, errors.New("proxy target resolution failed")
		}
		ip = ips[0]
	}
	ip = ip.Unmap()
	if ip.IsLoopback() || ip.IsUnspecified() {
		return netip.AddrPort{}, errors.New("test proxy cannot target loopback or itself")
	}
	return netip.AddrPortFrom(ip, uint16(port)), nil
}

func socksReply(c net.Conn, ok, denied bool, local net.Addr) error {
	code := byte(0)
	if !ok {
		code = 1
		if denied {
			code = 2
		}
	}
	address := netip.MustParseAddrPort("0.0.0.0:0")
	if local != nil {
		if a, err := netip.ParseAddrPort(local.String()); err == nil {
			address = a
		}
	}
	ip := address.Addr().Unmap()
	atyp := byte(1)
	if ip.Is6() {
		atyp = 4
	}
	b := append([]byte{5, code, 0, atyp}, ip.AsSlice()...)
	b = binary.BigEndian.AppendUint16(b, address.Port())
	_, err := c.Write(b)
	return err
}
