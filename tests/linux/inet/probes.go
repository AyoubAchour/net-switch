//go:build linux

package inet

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// A private CA exists only inside the harness run. The engine still uses Go's
// normal certificate validation; its namespace launcher supplies SSL_CERT_FILE.
func serveProbes(dir string, rec *recorder) error {
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Net Switch acceptance CA"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, pub, key)
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "probe-ca.pem"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}), 0644); err != nil {
		return err
	}
	leaf := func(serial int64, ips ...string) (tls.Certificate, error) {
		pubLeaf, keyLeaf, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return tls.Certificate{}, err
		}
		cert := &x509.Certificate{SerialNumber: big.NewInt(serial), NotBefore: ca.NotBefore, NotAfter: ca.NotAfter, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, KeyUsage: x509.KeyUsageDigitalSignature}
		for _, ip := range ips {
			cert.IPAddresses = append(cert.IPAddresses, net.ParseIP(ip))
		}
		der, err := x509.CreateCertificate(rand.Reader, cert, ca, pubLeaf, key)
		return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: keyLeaf}, err
	}
	valid, err := leaf(2, "1.1.1.1", "8.8.8.8", "9.9.9.9")
	if err != nil {
		return err
	}
	wrong, err := leaf(3, "127.0.0.1")
	if err != nil {
		return err
	}
	mode := func() string {
		b, _ := os.ReadFile(filepath.Join(dir, "probe-mode"))
		return strings.TrimSpace(string(b))
	}
	server := &http.Server{ReadHeaderTimeout: 5 * time.Second, TLSConfig: &tls.Config{MinVersion: tls.VersionTLS12, GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
		if mode() == "wrong-certificate" {
			return &wrong, nil
		}
		return &valid, nil
	}}}
	server.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch mode() {
		case "redirect":
			http.Redirect(w, r, "https://1.1.1.1/cdn-cgi/trace", http.StatusFound)
			return
		case "portal":
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, "<html>Sign in</html>")
			return
		}
		switch r.URL.Path {
		case "/cdn-cgi/trace":
			w.Header().Set("Content-Type", "text/plain")
			fmt.Fprintln(w, "ip=192.0.2.1")
		case "/resolve":
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{"Status":0}`)
		case "/dns-query":
			b, err := base64.RawURLEncoding.DecodeString(r.URL.Query().Get("dns"))
			if err != nil || len(b) < 12 {
				http.Error(w, "bad DNS query", 400)
				return
			}
			b[2] |= 0x80
			w.Header().Set("Content-Type", "application/dns-message")
			w.Write(b)
		default:
			http.NotFound(w, r)
		}
	})
	ln, err := listen(":443", rec)
	if err != nil {
		return err
	}
	go func() {
		if err := server.ServeTLS(ln, "", ""); err != nil {
			fmt.Fprintln(os.Stderr, "probe fixture:", err)
			os.Exit(3)
		}
	}()
	return nil
}
