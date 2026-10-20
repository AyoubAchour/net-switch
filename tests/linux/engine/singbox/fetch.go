package singbox

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"time"
)

// Pin is one verified download: the plain Linux tarball of a sing-box release.
type Pin struct {
	URL    string `json:"url"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}

// Pins is tests/linux/sing-box-linux.json: per version, per Go architecture.
type Pins struct {
	Note     string                    `json:"note"`
	Versions map[string]map[string]Pin `json:"versions"`
}

// PinnedVersion reads the sing-box version today's app ships from
// packaging/versions.json.
func PinnedVersion(versionsJSON string) (string, error) {
	data, err := os.ReadFile(versionsJSON)
	if err != nil {
		return "", err
	}
	var v struct {
		SingBox struct {
			Version string `json:"version"`
		} `json:"singBox"`
	}
	if err := json.Unmarshal(data, &v); err != nil {
		return "", fmt.Errorf("%s: %w", versionsJSON, err)
	}
	if v.SingBox.Version == "" {
		return "", fmt.Errorf("%s has no singBox.version", versionsJSON)
	}
	return v.SingBox.Version, nil
}

// LookupPin finds the tarball for a version and architecture.
func LookupPin(pinsJSON, version, arch string) (Pin, error) {
	data, err := os.ReadFile(pinsJSON)
	if err != nil {
		return Pin{}, err
	}
	var pins Pins
	if err := json.Unmarshal(data, &pins); err != nil {
		return Pin{}, fmt.Errorf("%s: %w", pinsJSON, err)
	}
	pin, ok := pins.Versions[version][arch]
	if !ok {
		return Pin{}, fmt.Errorf("%s has no %s tarball for sing-box %s, the version packaging/versions.json pins: add its URL, size and SHA-256 (the release asset's digest)", pinsJSON, arch, version)
	}
	if len(pin.SHA256) != 64 || pin.URL == "" || pin.Size <= 0 {
		return Pin{}, fmt.Errorf("%s: the %s %s entry needs url, size and a 64-digit sha256", pinsJSON, version, arch)
	}
	return pin, nil
}

// Download fetches the tarball, retrying, and checks its size and SHA-256.
func Download(ctx context.Context, pin Pin) ([]byte, error) {
	const maxAttempts = 4
	var lastErr error
	for attempt := 0; attempt < maxAttempts; attempt++ {
		if attempt > 0 {
			select {
			case <-time.After(time.Duration(attempt*5) * time.Second):
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
		data, err := get(ctx, pin.URL, pin.Size)
		if err == nil {
			err = Verify(data, pin)
		}
		if err != nil {
			lastErr = err
			continue
		}
		return data, nil
	}
	return nil, fmt.Errorf("download %s failed after %d attempts: %w", pin.URL, maxAttempts, lastErr)
}

func get(ctx context.Context, url string, size int64) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, size+1))
}

// Verify checks a download against its pin.
func Verify(data []byte, pin Pin) error {
	if int64(len(data)) != pin.Size {
		return fmt.Errorf("got %d bytes, the pin says %d", len(data), pin.Size)
	}
	sum := sha256.Sum256(data)
	if got := hex.EncodeToString(sum[:]); got != pin.SHA256 {
		return fmt.Errorf("SHA-256 %s doesn't match the pinned %s", got, pin.SHA256)
	}
	return nil
}

// Extract writes the tarball's sing-box and LICENSE into dest. The plain Linux
// build has nothing else we need (no libcronet.so, LINUX-PLAN.md section 0).
func Extract(tarball []byte, dest string) error {
	gz, err := gzip.NewReader(bytes.NewReader(tarball))
	if err != nil {
		return err
	}
	tr := tar.NewReader(gz)
	if err := os.MkdirAll(dest, 0o755); err != nil {
		return err
	}
	found := map[string]bool{}
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return err
		}
		name := path.Base(path.Clean(h.Name))
		if h.Typeflag != tar.TypeReg || (name != "sing-box" && name != "LICENSE") {
			continue
		}
		mode := os.FileMode(0o644)
		if name == "sing-box" {
			mode = 0o755
		}
		f, err := os.OpenFile(filepath.Join(dest, name), os.O_CREATE|os.O_WRONLY|os.O_TRUNC, mode)
		if err != nil {
			return err
		}
		_, err = io.Copy(f, io.LimitReader(tr, 512<<20))
		if cerr := f.Close(); err == nil {
			err = cerr
		}
		if err != nil {
			return err
		}
		found[name] = true
	}
	if !found["sing-box"] {
		return errors.New("the tarball has no sing-box program")
	}
	return nil
}
