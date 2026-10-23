package lifecycle_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func windowsNativeProbe(t *testing.T, data, address string) nativeProbeFixture {
	t.Helper()
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "native service proof CA"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, ca, ca, pub, key)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(data, "probe-test-ca.pem"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600); err != nil {
		t.Fatal(err)
	}
	leaf := func(serial int64, ip string) tls.Certificate {
		c := &x509.Certificate{SerialNumber: big.NewInt(serial), NotBefore: ca.NotBefore, NotAfter: ca.NotAfter, IPAddresses: []net.IP{net.ParseIP(ip)}, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
		b, err := x509.CreateCertificate(rand.Reader, c, ca, pub, key)
		if err != nil {
			t.Fatal(err)
		}
		return tls.Certificate{Certificate: [][]byte{b, der}, PrivateKey: key}
	}
	valid, wrong := leaf(2, "198.19.128.2"), leaf(3, "127.0.0.1")
	var bad atomic.Bool
	var mu sync.Mutex
	count, last := 0, ""
	server := &http.Server{ReadHeaderTimeout: 5 * time.Second, WriteTimeout: 5 * time.Second, MaxHeaderBytes: 8192,
		TLSConfig: &tls.Config{MinVersion: tls.VersionTLS12, GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
			if bad.Load() {
				return &wrong, nil
			}
			return &valid, nil
		}},
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			mu.Lock()
			count++
			last = r.Method + " " + r.URL.Path
			mu.Unlock()
			w.Header().Set("Location", "https://unexpected.invalid/")
			w.WriteHeader(302)
		})}
	l, err := net.Listen("tcp4", net.JoinHostPort(address, "0"))
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() { defer close(done); server.ServeTLS(l, "", "") }()
	t.Cleanup(func() { server.Close(); <-done })
	_, port, _ := net.SplitHostPort(l.Addr().String())
	return nativeProbeFixture{target: "198.19.128.2:" + port, wrong: func(_ *testing.T, v bool) { bad.Store(v) }, seen: func(*testing.T) (int, string) { mu.Lock(); defer mu.Unlock(); return count, last }}
}
