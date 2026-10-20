package singbox

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestDownloadRetriesRejectedBody(t *testing.T) {
	good := []byte("the verified tool archive")
	sum := sha256.Sum256(good)
	for _, kind := range []string{"hash", "size", "interrupted"} {
		t.Run(kind, func(t *testing.T) {
			var requests atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if requests.Add(1) == 1 {
					switch kind {
					case "hash":
						bad := bytes.Clone(good)
						bad[0] ^= 1
						w.Write(bad)
					case "size":
						w.Write(good[:len(good)-1])
					case "interrupted":
						w.Header().Set("Content-Length", strconv.Itoa(len(good)))
						w.Write(good[:len(good)/2])
					}
					return
				}
				w.Write(good)
			}))
			defer server.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			pin := Pin{URL: server.URL, SHA256: hex.EncodeToString(sum[:]), Size: int64(len(good))}
			data, err := Download(ctx, pin)
			t.Logf("%s: %d HTTP requests", kind, requests.Load())
			if err != nil || !bytes.Equal(data, good) || requests.Load() != 2 {
				t.Fatalf("rejected response was not replaced by a verified one: bytes=%q requests=%d error=%v", data, requests.Load(), err)
			}
		})
	}
}

func TestDownloadRejectsPersistentBody(t *testing.T) {
	good := []byte("the verified tool archive")
	sum := sha256.Sum256(good)
	bad := bytes.Clone(good)
	bad[0] ^= 1
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		w.Write(bad)
	}))
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	pin := Pin{URL: server.URL, SHA256: hex.EncodeToString(sum[:]), Size: int64(len(good))}
	data, err := Download(ctx, pin)
	t.Logf("persistent mismatch: %d HTTP requests", requests.Load())
	if err == nil || !strings.Contains(err.Error(), "SHA-256") || len(data) != 0 || requests.Load() != 4 {
		t.Fatalf("unverified body or unbounded attempts: bytes=%q requests=%d error=%v", data, requests.Load(), err)
	}
}

func tarball(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for name, body := range files {
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o755, Size: int64(len(body)), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestVerifyAndExtract(t *testing.T) {
	data := tarball(t, map[string]string{
		"sing-box-1.14.2-linux-amd64/sing-box":  "binary",
		"sing-box-1.14.2-linux-amd64/LICENSE":   "license",
		"sing-box-1.14.2-linux-amd64/README.md": "skipped",
	})
	sum := sha256.Sum256(data)
	pin := Pin{URL: "x", SHA256: hex.EncodeToString(sum[:]), Size: int64(len(data))}
	if err := Verify(data, pin); err != nil {
		t.Fatal(err)
	}
	bad := pin
	bad.SHA256 = "00" + pin.SHA256[2:]
	if Verify(data, bad) == nil {
		t.Fatal("a different hash must be rejected")
	}
	short := pin
	short.Size++
	if Verify(data, short) == nil {
		t.Fatal("a different size must be rejected")
	}
	dir := t.TempDir()
	if err := Extract(data, dir); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(filepath.Join(dir, "sing-box")); string(got) != "binary" {
		t.Fatalf("sing-box = %q", got)
	}
	if _, err := os.Stat(filepath.Join(dir, "README.md")); err == nil {
		t.Fatal("only sing-box and LICENSE are extracted")
	}
	if Extract(tarball(t, map[string]string{"x/LICENSE": "l"}), t.TempDir()) == nil {
		t.Fatal("a tarball without sing-box must be rejected")
	}
}

// The checked-in pins must cover the version today's app ships, on both
// architectures CI runs.
func TestPinsCoverShippedVersion(t *testing.T) {
	root := filepath.Join("..", "..", "..", "..")
	version, err := PinnedVersion(filepath.Join(root, "packaging", "versions.json"))
	if err != nil {
		t.Fatal(err)
	}
	for _, arch := range []string{"amd64", "arm64"} {
		if _, err := LookupPin(filepath.Join(root, "tests", "linux", "sing-box-linux.json"), version, arch); err != nil {
			t.Error(err)
		}
	}
}
