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
	f, err := trustedFile(s.path, unix.O_RDWR|unix.O_CREAT)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	// Establish the directory entry once. Append only changes this inode.
	if err := SyncDir(filepath.Dir(s.path)); err != nil {
		return nil, err
	}
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
	_, statErr := os.Lstat(s.path)
	f, err := trustedFile(s.path, unix.O_WRONLY|unix.O_APPEND|unix.O_CREAT)
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
	if errors.Is(statErr, os.ErrNotExist) {
		return SyncDir(filepath.Dir(s.path))
	}
	return nil
}

func (s diskStore) Compact(records []journal.Record) error {
	f, err := os.CreateTemp(filepath.Dir(s.path), ".engine-journal-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	defer f.Close()
	write := func(r journal.Record) error {
		b, err := json.Marshal(r)
		if err != nil {
			return err
		}
		sum := sha256.Sum256(b)
		return json.NewEncoder(f).Encode(diskRecord{b, hex.EncodeToString(sum[:])})
	}
	for _, r := range records {
		phase := r.Phase
		r.Phase = "intent"
		if err := write(r); err != nil {
			return err
		}
		if phase == "created" {
			r.Phase = phase
			if err := write(r); err != nil {
				return err
			}
		}
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(f.Name(), s.path); err != nil {
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

func trustedFile(path string, flags int) (*os.File, error) {
	fd, err := unix.Open(path, flags|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0600)
	if err != nil {
		return nil, &os.PathError{Op: "open private engine file", Path: path, Err: err}
	}
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		unix.Close(fd)
		return nil, err
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG || st.Mode&0777 != 0600 || st.Uid != uint32(os.Geteuid()) || st.Nlink != 1 {
		unix.Close(fd)
		return nil, fmt.Errorf("unsafe engine file %s: needs a private, singly linked regular file owned by this user", path)
	}
	return os.NewFile(uintptr(fd), path), nil
}

func (l fileLock) Acquire(ctx context.Context) (func() error, error) {
	f, err := trustedFile(l.path, unix.O_CREAT|unix.O_RDWR)
	if err != nil {
		return nil, err
	}
	fd := int(f.Fd())
	for {
		err := unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB)
		if err == nil {
			return f.Close, nil
		}
		if !errors.Is(err, unix.EWOULDBLOCK) {
			f.Close()
			return nil, err
		}
		select {
		case <-ctx.Done():
			f.Close()
			return nil, fmt.Errorf("engine owns the journal lock: %w", ctx.Err())
		case <-time.After(20 * time.Millisecond):
		}
	}
}
