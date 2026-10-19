//go:build linux

package linux

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/AyoubAchour/net-switch/internal/journal"
	"golang.org/x/sys/unix"
)

// diskStore uses checksummed JSON lines. Only a torn final line is recoverable;
// a complete corrupt record must never become permission to delete anything.
type diskStore struct{ path string }
type diskRecord struct {
	Record json.RawMessage `json:"record"`
	SHA256 string          `json:"sha256"`
}

func (s diskStore) Records() ([]journal.Record, error) {
	f, err := os.OpenFile(s.path, os.O_RDWR|os.O_CREATE, 0600)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	r := bufio.NewReader(f)
	var records []journal.Record
	var offset int64
	for {
		line, err := r.ReadBytes('\n')
		if errors.Is(err, io.EOF) {
			if len(line) != 0 {
				if err := f.Truncate(offset); err != nil {
					return nil, err
				}
				if err := f.Sync(); err != nil {
					return nil, err
				}
			}
			return records, nil
		}
		if err != nil {
			return nil, err
		}
		var envelope diskRecord
		if err := json.Unmarshal(line, &envelope); err != nil {
			return nil, fmt.Errorf("journal at %d: %w", offset, err)
		}
		sum := sha256.Sum256(envelope.Record)
		if hex.EncodeToString(sum[:]) != envelope.SHA256 {
			return nil, fmt.Errorf("journal checksum at %d", offset)
		}
		var record journal.Record
		if err := json.Unmarshal(envelope.Record, &record); err != nil {
			return nil, err
		}
		records = append(records, record)
		offset += int64(len(line))
	}
}

func (s diskStore) Append(r journal.Record) error {
	b, err := json.Marshal(r)
	if err != nil {
		return err
	}
	sum := sha256.Sum256(b)
	line, err := json.Marshal(diskRecord{b, hex.EncodeToString(sum[:])})
	if err != nil {
		return err
	}
	f, err := os.OpenFile(s.path, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0600)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err := f.Write(append(line, '\n')); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	return SyncDir(filepath.Dir(s.path))
}

func SyncDir(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}

type fileLock struct{ path string }

func (l fileLock) Acquire(ctx context.Context) (func() error, error) {
	fd, err := unix.Open(l.path, unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_CREAT|unix.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	for {
		err := unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB)
		if err == nil {
			return func() error { return unix.Close(fd) }, nil
		}
		if !errors.Is(err, unix.EWOULDBLOCK) {
			unix.Close(fd)
			return nil, err
		}
		select {
		case <-ctx.Done():
			unix.Close(fd)
			return nil, fmt.Errorf("engine owns the journal lock: %w", ctx.Err())
		case <-time.After(20 * time.Millisecond):
		}
	}
}
