//go:build windows

// A controlled QUIC v1 target and client; never used by the production app.
package main

import (
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
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"os"
	"runtime"
	"time"

	"github.com/AyoubAchour/net-switch/tests/windows/socket"
	"github.com/quic-go/quic-go"
)

func main() {
	if len(os.Args) == 2 && os.Args[1] == "version" {
		fmt.Printf("QUIC acceptance probe, quic-go v0.64.0, %s %s\n", runtime.Version(), runtime.GOARCH)
		return
	}
	if os.Getenv("GITHUB_ACTIONS") != "true" || os.Getenv("RUNNER_ENVIRONMENT") != "github-hosted" {
		log.Fatal("Hosted Windows runners only")
	}
	if err := execute(); err != nil {
		log.Fatal(err)
	}
}

func execute() error {
	f := flag.NewFlagSet("quicprobe", flag.ContinueOnError)
	serve := f.Bool("serve", false, "start controlled target")
	address := f.String("address", "", "target or listen address:port")
	source := f.String("source", "0.0.0.0", "source address")
	index := f.Int("interface", 0, "bind interface (zero uses app routing)")
	state := f.String("state", "", "server ready JSON")
	pin := f.String("certificate", "", "expected certificate SHA-256")
	if err := f.Parse(os.Args[1:]); err != nil {
		return err
	}
	if *address == "" {
		return errors.New("address is required")
	}
	config := net.ListenConfig{}
	if *index != 0 {
		config.Control = socket.BindInterface(*index)
	}
	listen := net.JoinHostPort(*source, "0")
	if *serve {
		listen = *address
	}
	udp, err := config.ListenPacket(context.Background(), "udp4", listen)
	if err != nil {
		return err
	}
	defer udp.Close()
	settings := &quic.Config{Versions: []quic.Version{quic.Version1}, HandshakeIdleTimeout: 5 * time.Second, MaxIdleTimeout: 10 * time.Second}
	if *serve {
		if *state == "" {
			return errors.New("state is required")
		}
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return err
		}
		certificate := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
		der, err := x509.CreateCertificate(rand.Reader, certificate, certificate, &key.PublicKey, key)
		if err != nil {
			return err
		}
		tlsConfig := &tls.Config{MinVersion: tls.VersionTLS13, NextProtos: []string{"netswitch-acceptance"}, Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}
		listener, err := quic.Listen(udp, tlsConfig, settings)
		if err != nil {
			return err
		}
		defer listener.Close()
		hash := sha256.Sum256(der)
		ready, _ := json.Marshal(map[string]any{"address": udp.LocalAddr().String(), "certificate": hex.EncodeToString(hash[:]), "pid": os.Getpid()})
		if err := os.WriteFile(*state, ready, 0600); err != nil {
			return err
		}
		for {
			conn, err := listener.Accept(context.Background())
			if err != nil {
				return err
			}
			go func() {
				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				defer cancel()
				stream, err := conn.AcceptStream(ctx)
				if err != nil {
					return
				}
				stream.SetDeadline(time.Now().Add(10 * time.Second))
				payload, err := io.ReadAll(io.LimitReader(stream, 2<<20))
				if err != nil {
					return
				}
				hash := sha256.Sum256(payload)
				json.NewEncoder(stream).Encode(map[string]any{"source": conn.RemoteAddr().String(), "bytes": len(payload), "sha256": hex.EncodeToString(hash[:])})
				stream.Close()
			}()
		}
	}
	if len(*pin) != 64 {
		return errors.New("certificate SHA-256 is required")
	}
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS13, NextProtos: []string{"netswitch-acceptance"}, InsecureSkipVerify: true,
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			if len(rawCerts) == 0 {
				return errors.New("missing certificate")
			}
			hash := sha256.Sum256(rawCerts[0])
			if hex.EncodeToString(hash[:]) != *pin {
				return errors.New("wrong test target certificate")
			}
			return nil
		}}
	remote, err := net.ResolveUDPAddr("udp4", *address)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	conn, err := quic.Dial(ctx, udp, remote, tlsConfig, settings)
	if err != nil {
		return err
	}
	defer conn.CloseWithError(0, "done")
	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		return err
	}
	stream.SetDeadline(time.Now().Add(15 * time.Second))
	payload := make([]byte, 1<<20)
	if _, err := rand.Read(payload); err != nil {
		return err
	}
	hash := sha256.Sum256(payload)
	if _, err := stream.Write(payload); err != nil {
		return err
	}
	if err := stream.Close(); err != nil {
		return err
	}
	var result struct {
		Source string `json:"source"`
		Bytes  int    `json:"bytes"`
		SHA256 string `json:"sha256"`
	}
	if err := json.NewDecoder(stream).Decode(&result); err != nil {
		return err
	}
	if result.Bytes != len(payload) || result.SHA256 != hex.EncodeToString(hash[:]) {
		return fmt.Errorf("corrupt QUIC payload: %+v", result)
	}
	return json.NewEncoder(os.Stdout).Encode(result)
}
