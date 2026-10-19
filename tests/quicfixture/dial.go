package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"github.com/quic-go/quic-go"
)

// Result is the client's report. Source, Bytes and SHA256 are the target's
// view of the upload, as the first version of this probe printed them.
type Result struct {
	Source         string  `json:"source"`
	Bytes          int64   `json:"bytes"`
	SHA256         string  `json:"sha256"`
	Download       int64   `json:"download"`
	DownloadSHA256 string  `json:"downloadSha256"`
	Local          string  `json:"local"`
	Version        string  `json:"version"`
	ALPN           string  `json:"alpn"`
	GSO            bool    `json:"gso"` // quic-go sent with UDP generic segmentation offload
	HandshakeMS    float64 `json:"handshakeMs"`
	TotalMS        float64 `json:"totalMs"`
}

func ms(d time.Duration) float64 { return float64(d.Microseconds()) / 1000 }

// dial runs one exchange against the target: a real QUIC v1 handshake with a
// pinned certificate, the upload, then the download, each checked by hash.
func dial(ctx context.Context, o options) (Result, error) {
	var r Result
	pin := strings.ToLower(o.certificate)
	tlsConf := &tls.Config{MinVersion: tls.VersionTLS13, NextProtos: []string{alpn},
		// The target's certificate is self-signed for the run; its hash is
		// the trust.
		InsecureSkipVerify: true,
		VerifyPeerCertificate: func(raw [][]byte, _ [][]*x509.Certificate) error {
			if len(raw) == 0 {
				return errors.New("the target sent no certificate")
			}
			sum := sha256.Sum256(raw[0])
			if hex.EncodeToString(sum[:]) != pin {
				return errors.New("not the test target's certificate")
			}
			return nil
		}}
	network := family(o.address)
	remote, err := net.ResolveUDPAddr(network, o.address)
	if err != nil {
		return r, err
	}
	pc, err := packetConn(ctx, network, net.JoinHostPort(o.source, "0"), o.iface)
	if err != nil {
		return r, err
	}
	defer pc.Close()
	// A *net.UDPConn as it is: quic-go then uses its batched, offloaded Linux
	// path (GSO, ECN, DF), which is what an engine has to carry.
	ctx, cancel := context.WithTimeout(ctx, o.timeout)
	defer cancel()
	start := time.Now()
	conn, err := quic.Dial(ctx, pc, remote, tlsConf, o.quicConfig())
	if err != nil {
		return r, fmt.Errorf("handshake: %w", err)
	}
	defer conn.CloseWithError(0, "done")
	r.HandshakeMS = ms(time.Since(start))
	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		return r, err
	}
	_ = stream.SetDeadline(start.Add(o.timeout))
	payload := make([]byte, o.upload)
	if _, err := rand.Read(payload); err != nil {
		return r, err
	}
	sum := sha256.Sum256(payload)
	if _, err := fmt.Fprintf(stream, header, o.upload, o.download); err != nil {
		return r, err
	}
	if _, err := stream.Write(payload); err != nil {
		return r, fmt.Errorf("upload: %w", err)
	}
	if err := stream.Close(); err != nil {
		return r, err
	}
	in := bufio.NewReader(stream)
	line, err := in.ReadString('\n')
	if err != nil {
		return r, fmt.Errorf("the target's answer: %w", err)
	}
	var reply Reply
	if err := json.Unmarshal([]byte(line), &reply); err != nil {
		return r, fmt.Errorf("the target's answer %q: %w", strings.TrimSpace(line), err)
	}
	r.Source, r.Bytes, r.SHA256 = reply.Source, reply.Bytes, reply.SHA256
	if reply.Bytes != o.upload || reply.SHA256 != hex.EncodeToString(sum[:]) {
		return r, fmt.Errorf("the upload arrived corrupt: %d of %d bytes, SHA-256 %s", reply.Bytes, o.upload, reply.SHA256)
	}
	h := sha256.New()
	got, err := io.Copy(h, io.LimitReader(in, o.download+1))
	if err != nil {
		return r, fmt.Errorf("download: %w", err)
	}
	r.Download, r.DownloadSHA256 = got, hex.EncodeToString(h.Sum(nil))
	if got != reply.Download || got != o.download || r.DownloadSHA256 != reply.DownloadSHA256 {
		return r, fmt.Errorf("the download arrived corrupt: %d of %d bytes, SHA-256 %s, the target sent %s", got, o.download, r.DownloadSHA256, reply.DownloadSHA256)
	}
	state := conn.ConnectionState()
	r.Local, r.Version, r.ALPN, r.GSO = pc.LocalAddr().String(), state.Version.String(), state.TLS.NegotiatedProtocol, state.GSO
	r.TotalMS = ms(time.Since(start))
	return r, nil
}
