//go:build linux

// Package inet is the fake internet's servers (role "inet") and the home
// routers' own pages (role "lan"). Every service tells the client the source
// address it saw, and the inet role also records, independently of any
// client, everything that reaches it: each TCP connection accepted, each UDP
// datagram (with its size), each DNS query, STUN request and ICMP echo. Cases
// use those records to prove what did or didn't get out. A record that can't
// be written stops the server, which fails the case: evidence is never
// silently lost.
package inet

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/AyoubAchour/net-switch/tests/linux/topo"
	"github.com/AyoubAchour/net-switch/tests/linux/wire"
)

// EventsFile is where the inet role records what reached it.
const EventsFile = "events.jsonl"

// Record is one observation.
type Record struct {
	T     int64  `json:"t"`    // Unix ms
	Kind  string `json:"kind"` // tcp, udp, dns, stun, poke, icmp
	Src   string `json:"src"`  // what the server saw: ip or ip:port
	Dst   string `json:"dst,omitempty"`
	Len   int    `json:"len,omitempty"` // UDP payload bytes
	Proto string `json:"proto,omitempty"`
	Data  string `json:"data,omitempty"` // payload prefix, query name...
}

type recorder struct {
	mu sync.Mutex
	f  *os.File
}

func (r *recorder) add(rec Record) {
	if r == nil {
		return
	}
	rec.T = time.Now().UnixMilli()
	line, err := json.Marshal(rec)
	if err == nil {
		r.mu.Lock()
		_, err = r.f.Write(append(line, '\n'))
		r.mu.Unlock()
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "recording failed, stopping: %v\n", err)
		os.Exit(3)
	}
}

func prefix(b []byte, n int) string {
	if len(b) > n {
		b = b[:n]
	}
	return string(b)
}

// Main is "nsaccept serve". It runs until killed.
func Main(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	role := fs.String("role", "inet", `"inet" (the internet) or "lan" (a home router's own pages)`)
	out := fs.String("out", "", "folder for events.jsonl (role inet)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	var errs []error
	switch *role {
	case "lan":
		errs = append(errs, serveTCP(":"+strconv.Itoa(wire.PortWhoami), nil, whoami), serveHTTP(":"+strconv.Itoa(wire.PortHTTP), nil))
	case "inet":
		if *out == "" {
			return errors.New("serve --role inet needs --out")
		}
		f, err := os.OpenFile(filepath.Join(*out, EventsFile), os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
		if err != nil {
			return err
		}
		rec := &recorder{f: f}
		errs = append(errs,
			serveTCP(":"+strconv.Itoa(wire.PortWhoami), rec, whoami),
			serveTCP(":"+strconv.Itoa(wire.PortStream), rec, stream),
			serveTCP(":"+strconv.Itoa(wire.PortHold), rec, holdOpen),
			serveTCP(":"+strconv.Itoa(wire.PortBulk), rec, bulk),
			serveTCP(":"+strconv.Itoa(wire.PortDNS), rec, dnsTCP(rec)),
			serveProbes(*out, rec),
			serveHTTP(":"+strconv.Itoa(wire.PortHTTP), rec),
		)
		echoAddrs := append([]netip.Addr{topo.Server4, topo.Server4b, topo.Third4, topo.Server6, topo.Server6b}, topo.ManyServers()...)
		for _, addr := range echoAddrs {
			errs = append(errs, serveUDP(netip.AddrPortFrom(addr, wire.PortUDPEcho), func(c *net.UDPConn, src netip.AddrPort, b []byte) {
				rec.add(Record{Kind: "udp", Src: src.String(), Dst: c.LocalAddr().String(), Len: len(b), Data: prefix(b, 80)})
				_, _ = c.WriteToUDPAddrPort(wire.EchoReply(src, b), src)
			}))
		}
		for _, s := range []struct {
			addr netip.Addr
			port uint16
		}{{topo.Server4, wire.PortSTUN1}, {topo.Server4b, wire.PortSTUN2}, {topo.Server6, wire.PortSTUN1}, {topo.Server6b, wire.PortSTUN2}} {
			errs = append(errs, serveUDP(netip.AddrPortFrom(s.addr, s.port), stun(rec)))
		}
		for _, addr := range []netip.Addr{topo.Server4, topo.Server6} {
			errs = append(errs, serveUDP(netip.AddrPortFrom(addr, wire.PortDNS), dnsUDP(rec)))
		}
		third, err := net.ListenUDP("udp", net.UDPAddrFromAddrPort(netip.AddrPortFrom(topo.Third4, wire.PortPokeSrc)))
		errs = append(errs, err)
		if err == nil {
			errs = append(errs, serveUDP(netip.AddrPortFrom(topo.Server4, wire.PortPoke), poker(rec, third)))
		}
		errs = append(errs, observeICMP("ip4:icmp", "0.0.0.0", 8, rec), observeICMP("ip6:ipv6-icmp", "::", 128, rec))
	default:
		return fmt.Errorf("unknown role %q", *role)
	}
	if err := errors.Join(errs...); err != nil {
		return err
	}
	fmt.Println("serving")
	select {}
}

func addrString(a net.Addr) string {
	if ap, err := netip.ParseAddrPort(a.String()); err == nil {
		return netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port()).String()
	}
	return a.String()
}

// recordingListener records every connection it accepts.
type recordingListener struct {
	net.Listener
	rec *recorder
}

func (l recordingListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err == nil {
		l.rec.add(Record{Kind: "tcp", Src: addrString(conn.RemoteAddr()), Dst: addrString(conn.LocalAddr())})
	}
	return conn, err
}

func listen(addr string, rec *recorder) (net.Listener, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil || rec == nil {
		return ln, err
	}
	return recordingListener{ln, rec}, nil
}

func serveTCP(addr string, rec *recorder, handle func(net.Conn)) error {
	ln, err := listen(addr, rec)
	if err != nil {
		return err
	}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				time.Sleep(10 * time.Millisecond)
				continue
			}
			go func() {
				defer conn.Close()
				handle(conn)
			}()
		}
	}()
	return nil
}

func remoteIP(conn net.Conn) string {
	if ap, err := netip.ParseAddrPort(conn.RemoteAddr().String()); err == nil {
		return ap.Addr().Unmap().String()
	}
	return conn.RemoteAddr().String()
}

func whoami(conn net.Conn) {
	_, _ = io.WriteString(conn, remoteIP(conn)+"\n")
}

func stream(conn net.Conn) {
	ip := remoteIP(conn)
	scanner := bufio.NewScanner(conn)
	for scanner.Scan() {
		line := strings.TrimPrefix(scanner.Text(), "ping ")
		if _, err := fmt.Fprintf(conn, "pong %s %s\n", line, ip); err != nil {
			return
		}
	}
}

// holdOpen keeps a connection until the client closes it, sending nothing:
// tens of thousands of them cost a socket and a small goroutine each.
func holdOpen(conn net.Conn) {
	var b [1]byte
	for {
		if _, err := conn.Read(b[:]); err != nil {
			return
		}
	}
}

func bulk(conn net.Conn) {
	_ = conn.SetDeadline(time.Now().Add(5 * time.Minute))
	reader := bufio.NewReader(conn)
	line, err := reader.ReadString('\n')
	if err != nil {
		return
	}
	verb, n, err := wire.ParseBulkRequest(strings.TrimSpace(line))
	if err != nil {
		_, _ = io.WriteString(conn, "ERR "+err.Error()+"\n")
		return
	}
	switch verb {
	case "GET":
		_, _ = io.Copy(conn, wire.Pattern(n))
	case "FLOOD":
		flood(conn, time.Duration(n)*time.Millisecond)
	case "PUT":
		h := sha256.New()
		got, err := io.CopyN(h, reader, n)
		if err != nil {
			_, _ = fmt.Fprintf(conn, "ERR got %d of %d bytes: %v\n", got, n, err)
			return
		}
		_, _ = io.WriteString(conn, hex.EncodeToString(h.Sum(nil))+"\n")
	}
}

// flood sends wire.FloodPattern as fast as the connection takes it for d,
// then one byte of it every 100 ms, so the flow keeps moving, until the
// client closes (or 10 minutes pass).
func flood(conn net.Conn, d time.Duration) {
	src := wire.FloodPattern()
	buf := make([]byte, 64<<10)
	for end := time.Now().Add(d); time.Now().Before(end); {
		if _, err := io.ReadFull(src, buf); err != nil {
			return
		}
		if _, err := conn.Write(buf); err != nil {
			return
		}
	}
	_ = conn.SetDeadline(time.Now().Add(10 * time.Minute))
	one := buf[:1]
	for {
		if _, err := io.ReadFull(src, one); err != nil {
			return
		}
		if _, err := conn.Write(one); err != nil {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func dnsName(q wire.DNSQuery) string { return fmt.Sprintf("%s/%d", q.Name, q.Type) }

func dnsTCP(rec *recorder) func(net.Conn) {
	return func(conn net.Conn) {
		_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
		src, err := netip.ParseAddrPort(conn.RemoteAddr().String())
		if err != nil {
			return
		}
		for {
			var size [2]byte
			if _, err := io.ReadFull(conn, size[:]); err != nil {
				return
			}
			msg := make([]byte, binary.BigEndian.Uint16(size[:]))
			if _, err := io.ReadFull(conn, msg); err != nil {
				return
			}
			q, err := wire.ParseDNSQuery(msg)
			if err != nil {
				return
			}
			rec.add(Record{Kind: "dns", Proto: "tcp", Src: addrString(conn.RemoteAddr()), Dst: addrString(conn.LocalAddr()), Data: dnsName(q)})
			answer := wire.DNSAnswer(q, src.Addr(), 0)
			if _, err := conn.Write(append(binary.BigEndian.AppendUint16(nil, uint16(len(answer))), answer...)); err != nil {
				return
			}
		}
	}
}

func serveHTTP(addr string, rec *recorder) error {
	ln, err := listen(addr, rec)
	if err != nil {
		return err
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/slow" {
			ms, _ := strconv.Atoi(r.URL.Query().Get("ms"))
			select {
			case <-time.After(time.Duration(min(max(ms, 0), 60_000)) * time.Millisecond):
			case <-r.Context().Done():
				return
			}
		}
		host := r.RemoteAddr
		if ap, err := netip.ParseAddrPort(host); err == nil {
			host = ap.Addr().Unmap().String()
		}
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("Connection", "close")
		_, _ = io.WriteString(w, host+"\n")
	})
	go func() { _ = (&http.Server{Handler: mux, ReadHeaderTimeout: 10 * time.Second}).Serve(ln) }()
	return nil
}

func serveUDP(addr netip.AddrPort, handle func(c *net.UDPConn, src netip.AddrPort, b []byte)) error {
	conn, err := net.ListenUDP("udp", net.UDPAddrFromAddrPort(addr))
	if err != nil {
		return fmt.Errorf("listen udp %s: %w", addr, err)
	}
	// 4 MiB, past net.core.rmem_max (the server runs as root): an overload
	// case must measure the engine, not datagrams lost at the server.
	raw, err := conn.SyscallConn()
	if err != nil {
		return err
	}
	var serr error
	if err := raw.Control(func(fd uintptr) {
		serr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_RCVBUFFORCE, 4<<20)
		if serr == nil && addr.Addr().Is4() {
			// Replies without DF, as DNS servers send them: a big answer is
			// fragmented on a smaller path instead of lost while this end
			// learns the path MTU. (10, 0: IP_MTU_DISCOVER, IP_PMTUDISC_DONT.)
			serr = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IP, 10, 0)
		}
	}); err != nil || serr != nil {
		return fmt.Errorf("receive buffer for %s: %v %v", addr, err, serr)
	}
	go func() {
		buf := make([]byte, 65536)
		for {
			n, src, err := conn.ReadFromUDPAddrPort(buf)
			if err != nil {
				time.Sleep(10 * time.Millisecond)
				continue
			}
			handle(conn, netip.AddrPortFrom(src.Addr().Unmap(), src.Port()), bytes.Clone(buf[:n]))
		}
	}()
	return nil
}

func stun(rec *recorder) func(c *net.UDPConn, src netip.AddrPort, b []byte) {
	return func(c *net.UDPConn, src netip.AddrPort, b []byte) {
		txid, err := wire.ParseSTUNRequest(b)
		if err != nil {
			return
		}
		rec.add(Record{Kind: "stun", Src: src.String(), Dst: c.LocalAddr().String(), Len: len(b)})
		_, _ = c.WriteToUDPAddrPort(wire.STUNResponse(txid, src), src)
	}
}

func dnsUDP(rec *recorder) func(c *net.UDPConn, src netip.AddrPort, b []byte) {
	return func(c *net.UDPConn, src netip.AddrPort, b []byte) {
		q, err := wire.ParseDNSQuery(b)
		if err != nil {
			return
		}
		rec.add(Record{Kind: "dns", Proto: "udp", Src: src.String(), Dst: c.LocalAddr().String(), Data: dnsName(q)})
		limit := 512
		if q.EDNS > 512 {
			limit = min(int(q.EDNS), 4096)
		}
		_, _ = c.WriteToUDPAddrPort(wire.DNSAnswer(q, src.Addr(), limit), src)
	}
}

// poker answers "poke <token>" on its own socket, and also sends the token to
// the same address from a host the client never contacted.
func poker(rec *recorder, third *net.UDPConn) func(c *net.UDPConn, src netip.AddrPort, b []byte) {
	return func(c *net.UDPConn, src netip.AddrPort, b []byte) {
		token, ok := strings.CutPrefix(string(b), "poke ")
		if !ok {
			return
		}
		rec.add(Record{Kind: "poke", Src: src.String(), Dst: c.LocalAddr().String(), Data: token})
		_, _ = c.WriteToUDPAddrPort([]byte("ack "+src.String()), src)
		_, _ = third.WriteToUDPAddrPort([]byte("poke "+token+" from "+third.LocalAddr().String()), src)
	}
}

// observeICMP records echo requests (type want) the namespace receives.
func observeICMP(network, addr string, want byte, rec *recorder) error {
	conn, err := net.ListenPacket(network, addr)
	if err != nil {
		return fmt.Errorf("listen %s: %w", network, err)
	}
	go func() {
		buf := make([]byte, 65536)
		for {
			n, from, err := conn.ReadFrom(buf)
			if err != nil {
				time.Sleep(10 * time.Millisecond)
				continue
			}
			if n < 8 || buf[0] != want {
				continue
			}
			rec.add(Record{Kind: "icmp", Src: from.String(), Len: n - 8, Data: prefix(buf[8:n], 80)})
		}
	}()
	return nil
}

// ReadRecords reads the events the inet role wrote. Strict: the file must
// exist, and every complete line must parse; only a final line still being
// written (no newline yet) is left for the next read.
func ReadRecords(path string) ([]Record, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("the fake internet's records: %w", err)
	}
	if i := bytes.LastIndexByte(data, '\n'); i >= 0 {
		data = data[:i+1]
	} else {
		data = nil
	}
	var out []Record
	for n, line := range strings.Split(strings.TrimSuffix(string(data), "\n"), "\n") {
		if line == "" {
			continue
		}
		var rec Record
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			return nil, fmt.Errorf("%s line %d is malformed: %w", path, n+1, err)
		}
		out = append(out, rec)
	}
	return out, nil
}

// WaitRecords polls the records until match finds what it wants or the time
// is up. A read error ends it at once.
func WaitRecords(ctx context.Context, path string, timeout time.Duration, match func([]Record) bool) ([]Record, bool, error) {
	deadline := time.Now().Add(timeout)
	for {
		recs, err := ReadRecords(path)
		if err != nil {
			return nil, false, err
		}
		if match(recs) {
			return recs, true, nil
		}
		if time.Now().After(deadline) || ctx.Err() != nil {
			return recs, false, nil
		}
		time.Sleep(100 * time.Millisecond)
	}
}
