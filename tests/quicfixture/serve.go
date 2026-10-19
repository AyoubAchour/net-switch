package main

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	mrand "math/rand/v2"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
)

const alpn = "netswitch-acceptance"

// header opens every exchange: "NSQUIC1 <upload> <download>\n", then the
// upload. The target answers with a Reply line, then the download.
const header = "NSQUIC1 %d %d\n"

// Reply is the target's answer line: what it received, and the hash of what
// follows. Source, Bytes and SHA256 are what the first version of this probe
// answered, so its callers still read them.
type Reply struct {
	Source         string `json:"source"`
	Bytes          int64  `json:"bytes"`
	SHA256         string `json:"sha256"`
	Download       int64  `json:"download"`
	DownloadSHA256 string `json:"downloadSha256"`
}

// Record is one connection as the target saw it (--records).
type Record struct {
	T             int64  `json:"t"` // Unix ms when it ended
	Remote        string `json:"remote"`
	Local         string `json:"local"`
	Version       string `json:"version"`
	UploadBytes   int64  `json:"uploadBytes"`
	UploadSHA256  string `json:"uploadSha256"`
	DownloadBytes int64  `json:"downloadBytes"`
	// Datagrams is how many UDP datagrams came from the remote, and
	// MaxDatagram the largest UDP payload among them.
	Datagrams   int    `json:"datagrams"`
	MaxDatagram int    `json:"maxDatagram"`
	Err         string `json:"err,omitempty"`
}

type ready struct {
	Address     string   `json:"address"` // the first, for single-address callers
	Addresses   []string `json:"addresses"`
	Certificate string   `json:"certificate"`
	PID         int      `json:"pid"`
}

type server struct {
	cert      string
	addresses []string
	listeners []*quic.Listener
	conns     []net.PacketConn
	records   *os.File
	recMu     sync.Mutex
	wg        sync.WaitGroup
}

func (s *server) ready() ready {
	return ready{Address: s.addresses[0], Addresses: s.addresses, Certificate: s.cert, PID: os.Getpid()}
}

// listen starts the target on every address in o.address.
func listen(ctx context.Context, o options) (*server, error) {
	cert, sum, err := certificate()
	if err != nil {
		return nil, err
	}
	s := &server{cert: sum}
	if o.records != "" {
		if s.records, err = os.OpenFile(o.records, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644); err != nil {
			return nil, err
		}
	}
	tlsConf := &tls.Config{MinVersion: tls.VersionTLS13, NextProtos: []string{alpn}, Certificates: []tls.Certificate{cert}}
	for _, address := range strings.Split(o.address, ",") {
		pc, err := packetConn(ctx, family(address), address, o.iface)
		if err != nil {
			return nil, errors.Join(err, s.close())
		}
		s.conns = append(s.conns, pc)
		var conn net.PacketConn = pc
		var sizes *sizeConn
		if s.records != nil {
			// Datagram sizes, one ReadFrom per datagram: this costs the
			// target quic-go's batched and offloaded receive path, which isn't
			// what's under test (the client's path is).
			sizes = &sizeConn{PacketConn: pc, seen: map[string]*seen{}}
			conn = sizes
		}
		ln, err := quic.Listen(conn, tlsConf, o.quicConfig())
		if err != nil {
			return nil, errors.Join(err, s.close())
		}
		s.listeners = append(s.listeners, ln)
		s.addresses = append(s.addresses, pc.LocalAddr().String())
		s.wg.Go(func() { s.accept(ln, sizes) })
	}
	return s, nil
}

func (s *server) close() error {
	var errs []error
	for _, ln := range s.listeners {
		errs = append(errs, ln.Close())
	}
	for _, pc := range s.conns {
		errs = append(errs, pc.Close())
	}
	s.wg.Wait()
	if s.records != nil {
		errs = append(errs, s.records.Close())
	}
	return errors.Join(errs...)
}

func (s *server) accept(ln *quic.Listener, sizes *sizeConn) {
	for {
		conn, err := ln.Accept(context.Background())
		if err != nil {
			return
		}
		s.wg.Go(func() { s.handle(conn, sizes) })
	}
}

func (s *server) handle(conn *quic.Conn, sizes *sizeConn) {
	rec := Record{Remote: conn.RemoteAddr().String(), Local: conn.LocalAddr().String(), Version: conn.ConnectionState().Version.String()}
	err := s.exchange(conn, &rec)
	if err != nil {
		rec.Err = err.Error()
		_ = conn.CloseWithError(1, "exchange failed")
	}
	// The client closes once it has everything; count its datagrams after.
	select {
	case <-conn.Context().Done():
	case <-time.After(10 * time.Second):
		_ = conn.CloseWithError(0, "done")
	}
	if sizes != nil {
		got := sizes.of(conn.RemoteAddr())
		rec.Datagrams, rec.MaxDatagram = got.count, got.max
	}
	rec.T = time.Now().UnixMilli()
	s.write(rec)
}

func (s *server) exchange(conn *quic.Conn, rec *Record) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	stream, err := conn.AcceptStream(ctx)
	if err != nil {
		return err
	}
	defer stream.Close()
	_ = stream.SetDeadline(time.Now().Add(30 * time.Second))
	in := bufio.NewReaderSize(io.LimitReader(stream, limit+64), 64<<10)
	line, err := in.ReadString('\n')
	if err != nil {
		return fmt.Errorf("reading the header: %w", err)
	}
	var upload, download int64
	if _, err := fmt.Sscanf(line, header, &upload, &download); err != nil || upload < 0 || upload > limit || download < 0 || download > limit {
		return fmt.Errorf("bad header %q", strings.TrimSpace(line))
	}
	h := sha256.New()
	got, err := io.CopyN(h, in, upload)
	rec.UploadBytes, rec.UploadSHA256 = got, hex.EncodeToString(h.Sum(nil))
	if err != nil {
		return fmt.Errorf("got %d of %d bytes: %w", got, upload, err)
	}
	seed := randomSeed()
	reply := Reply{Source: rec.Remote, Bytes: got, SHA256: rec.UploadSHA256, Download: download, DownloadSHA256: patternSHA256(seed, download)}
	line2, err := json.Marshal(reply)
	if err != nil {
		return err
	}
	if _, err := stream.Write(append(line2, '\n')); err != nil {
		return err
	}
	sent, err := io.Copy(stream, pattern(seed, download))
	rec.DownloadBytes = sent
	return err
}

func (s *server) write(rec Record) {
	if s.records == nil {
		return
	}
	line, _ := json.Marshal(rec)
	s.recMu.Lock()
	defer s.recMu.Unlock()
	if _, err := s.records.Write(append(line, '\n')); err != nil {
		// Evidence that can't be written must not look like nothing happened.
		fmt.Fprintf(os.Stderr, "writing a record failed, stopping: %v\n", err)
		os.Exit(3)
	}
}

// certificate is a fresh self-signed certificate and its SHA-256, which the
// client pins.
func certificate() (tls.Certificate, string, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, "", err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 62))
	if err != nil {
		return tls.Certificate{}, "", err
	}
	tmpl := &x509.Certificate{SerialNumber: serial, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, "", err
	}
	sum := sha256.Sum256(der)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, hex.EncodeToString(sum[:]), nil
}

func randomSeed() [32]byte {
	var seed [32]byte
	_, _ = rand.Read(seed[:])
	return seed
}

// pattern is n bytes the target derives from a seed, so it can hash them
// before sending them.
func pattern(seed [32]byte, n int64) io.Reader {
	return io.LimitReader(mrand.NewChaCha8(seed), n)
}

func patternSHA256(seed [32]byte, n int64) string {
	h := sha256.New()
	_, _ = io.Copy(h, pattern(seed, n))
	return hex.EncodeToString(h.Sum(nil))
}

// sizeConn notes every datagram's source and size as it's read.
type sizeConn struct {
	net.PacketConn
	mu   sync.Mutex
	seen map[string]*seen
}

type seen struct{ count, max int }

func (c *sizeConn) ReadFrom(b []byte) (int, net.Addr, error) {
	n, addr, err := c.PacketConn.ReadFrom(b)
	if err == nil {
		c.mu.Lock()
		s := c.seen[addr.String()]
		if s == nil {
			s = &seen{}
			c.seen[addr.String()] = s
		}
		s.count++
		s.max = max(s.max, n)
		c.mu.Unlock()
	}
	return n, addr, err
}

func (c *sizeConn) of(addr net.Addr) seen {
	c.mu.Lock()
	defer c.mu.Unlock()
	if s := c.seen[addr.String()]; s != nil {
		return *s
	}
	return seen{}
}

// family is "udp6" for an IPv6 "[ip]:port", else "udp4".
func family(address string) string {
	if host, _, err := net.SplitHostPort(address); err == nil && strings.Contains(host, ":") {
		return "udp6"
	}
	return "udp4"
}

// packetConn is a UDP socket, bound to an interface when iface isn't 0.
func packetConn(ctx context.Context, network, address string, iface int) (*net.UDPConn, error) {
	lc := net.ListenConfig{}
	if iface != 0 {
		lc.Control = bindInterface(iface)
	}
	pc, err := lc.ListenPacket(ctx, network, address)
	if err != nil {
		return nil, err
	}
	return pc.(*net.UDPConn), nil
}
