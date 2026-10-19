package singbox

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

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
