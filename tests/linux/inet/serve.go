//go:build linux

// Package inet is the fake internet's servers (role "inet") and the home
// routers' own pages (role "lan"). Every service tells the client the source
// address it saw; the UDP echo and ICMP observer also log what they saw, so a
// case can check traffic that never got an answer.
package inet

import (
	"bufio"
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
	"time"

	"github.com/AyoubAchour/net-switch/tests/linux/topo"
	"github.com/AyoubAchour/net-switch/tests/linux/wire"
)

// Record is one observation in udp.jsonl or icmp.jsonl.
type Record struct {
	T    int64  `json:"t"` // Unix ms
	Kind string `json:"kind"`
	Src  string `json:"src"`
	Dst  string `json:"dst,omitempty"`
	Data string `json:"data"`
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
	line, _ := json.Marshal(rec)
	r.mu.Lock()
	defer r.mu.Unlock()
	_, _ = r.f.Write(append(line, '\n'))
}

func newRecorder(dir, name string) (*recorder, error) {
	f, err := os.OpenFile(filepath.Join(dir, name), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return nil, err
	}
	return &recorder{f: f}, nil
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
	out := fs.String("out", "", "folder for udp.jsonl and icmp.jsonl (role inet)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	var errs []error
	switch *role {
	case "lan":
		errs = append(errs, serveTCP(":"+strconv.Itoa(wire.PortWhoami), whoami), serveHTTP(":"+strconv.Itoa(wire.PortHTTP)))
	case "inet":
		if *out == "" {
			return errors.New("serve --role inet needs --out")
		}
		udpLog, err := newRecorder(*out, "udp.jsonl")
		if err != nil {
			return err
		}
		icmpLog, err := newRecorder(*out, "icmp.jsonl")
		if err != nil {
			return err
		}
		errs = append(errs,
			serveTCP(":"+strconv.Itoa(wire.PortWhoami), whoami),
			serveTCP(":"+strconv.Itoa(wire.PortStream), stream),
			serveTCP(":"+strconv.Itoa(wire.PortBulk), bulk),
			serveTCP(":"+strconv.Itoa(wire.PortDNS), dnsTCP),
			serveHTTP(":"+strconv.Itoa(wire.PortHTTP)),
		)
		echoAddrs := append([]netip.Addr{topo.Server4, topo.Server4b, topo.Third4, topo.Server6, topo.Server6b}, topo.ManyServers()...)
		for _, addr := range echoAddrs {
			errs = append(errs, serveUDP(netip.AddrPortFrom(addr, wire.PortUDPEcho), func(c *net.UDPConn, src netip.AddrPort, b []byte) {
				udpLog.add(Record{Kind: "udp", Src: src.String(), Dst: c.LocalAddr().String(), Data: prefix(b, 80)})
				_, _ = c.WriteToUDPAddrPort(wire.EchoReply(src, b), src)
			}))
		}
		for _, s := range []struct {
			addr netip.Addr
			port uint16
		}{{topo.Server4, wire.PortSTUN1}, {topo.Server4b, wire.PortSTUN2}, {topo.Server6, wire.PortSTUN1}, {topo.Server6b, wire.PortSTUN2}} {
			errs = append(errs, serveUDP(netip.AddrPortFrom(s.addr, s.port), stun))
		}
		for _, addr := range []netip.Addr{topo.Server4, topo.Server6} {
			errs = append(errs, serveUDP(netip.AddrPortFrom(addr, wire.PortDNS), dnsUDP))
		}
		third, err := net.ListenUDP("udp", net.UDPAddrFromAddrPort(netip.AddrPortFrom(topo.Third4, wire.PortPokeSrc)))
		errs = append(errs, err)
		if err == nil {
			errs = append(errs, serveUDP(netip.AddrPortFrom(topo.Server4, wire.PortPoke), poker(third)))
		}
		errs = append(errs, observeICMP("ip4:icmp", "0.0.0.0", 8, icmpLog), observeICMP("ip6:ipv6-icmp", "::", 128, icmpLog))
	default:
		return fmt.Errorf("unknown role %q", *role)
	}
	if err := errors.Join(errs...); err != nil {
		return err
	}
	fmt.Println("serving")
	select {}
}

func serveTCP(addr string, handle func(net.Conn)) error {
	ln, err := net.Listen("tcp", addr)
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

func dnsTCP(conn net.Conn) {
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
		answer := wire.DNSAnswer(q, src.Addr(), 0)
		if _, err := conn.Write(append(binary.BigEndian.AppendUint16(nil, uint16(len(answer))), answer...)); err != nil {
			return
		}
	}
}

func serveHTTP(addr string) error {
	ln, err := net.Listen("tcp", addr)
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
	go func() {
		buf := make([]byte, 65536)
		for {
			n, src, err := conn.ReadFromUDPAddrPort(buf)
			if err != nil {
				time.Sleep(10 * time.Millisecond)
				continue
			}
			handle(conn, netip.AddrPortFrom(src.Addr().Unmap(), src.Port()), append([]byte(nil), buf[:n]...))
		}
	}()
	return nil
}

func stun(c *net.UDPConn, src netip.AddrPort, b []byte) {
	txid, err := wire.ParseSTUNRequest(b)
	if err != nil {
		return
	}
	_, _ = c.WriteToUDPAddrPort(wire.STUNResponse(txid, src), src)
}

func dnsUDP(c *net.UDPConn, src netip.AddrPort, b []byte) {
	q, err := wire.ParseDNSQuery(b)
	if err != nil {
		return
	}
	limit := 512
	if q.EDNS > 512 {
		limit = min(int(q.EDNS), 4096)
	}
	_, _ = c.WriteToUDPAddrPort(wire.DNSAnswer(q, src.Addr(), limit), src)
}

// poker answers "poke <token>" on its own socket, and also sends the token to
// the same address from a host the client never contacted.
func poker(third *net.UDPConn) func(c *net.UDPConn, src netip.AddrPort, b []byte) {
	return func(c *net.UDPConn, src netip.AddrPort, b []byte) {
		token, ok := strings.CutPrefix(string(b), "poke ")
		if !ok {
			return
		}
		_, _ = c.WriteToUDPAddrPort([]byte("ack "+src.String()), src)
		_, _ = third.WriteToUDPAddrPort([]byte("poke "+token+" from "+third.LocalAddr().String()), src)
	}
}

// observeICMP logs echo requests (type want) the namespace receives.
func observeICMP(network, addr string, want byte, log *recorder) error {
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
			log.add(Record{Kind: "icmp", Src: from.String(), Data: prefix(buf[8:n], 80)})
		}
	}()
	return nil
}

// ReadRecords reads a .jsonl log the inet role wrote.
func ReadRecords(path string) ([]Record, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	var out []Record
	for _, line := range strings.Split(string(data), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		var rec Record
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			continue // a line being written right now
		}
		out = append(out, rec)
	}
	return out, nil
}

// WaitRecords polls a log until match finds what it wants or the time is up.
func WaitRecords(ctx context.Context, path string, timeout time.Duration, match func([]Record) bool) ([]Record, bool) {
	deadline := time.Now().Add(timeout)
	for {
		recs, _ := ReadRecords(path)
		if match(recs) {
			return recs, true
		}
		if time.Now().After(deadline) || ctx.Err() != nil {
			return recs, false
		}
		time.Sleep(100 * time.Millisecond)
	}
}
