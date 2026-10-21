package journal

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sync"
)

const RecordLimit = 1 << 20

type envelope struct {
	Record json.RawMessage `json:"record"`
	Hash   string          `json:"sha256"`
}

// FileStore is an fsynced append journal. The platform supplies directory
// durability and creates the parent with the required ACL/mode. SyncParent is
// required so a newly created journal cannot disappear after an OS mutation.
type FileStore struct {
	Path       string
	SyncParent func(string) error
	mu         sync.Mutex
	dirty      bool
}

func (f *FileStore) Records() ([]Record, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	file, err := os.OpenFile(f.Path, os.O_RDWR, 0600)
	if errors.Is(err, os.ErrNotExist) {
		f.dirty = false
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer file.Close()
	r := bufio.NewReaderSize(file, 4096)
	var records []Record
	var offset int64
	for {
		var line []byte
		oversize := false
		for {
			part, readErr := r.ReadSlice('\n')
			if len(line)+len(part) > RecordLimit {
				oversize = true
			}
			if !oversize {
				line = append(line, part...)
			}
			err = readErr
			if err != bufio.ErrBufferFull {
				break
			}
		}
		if err == io.EOF {
			if len(line) > 0 || oversize {
				if err := file.Truncate(offset); err != nil {
					return nil, err
				}
				if err := file.Sync(); err != nil {
					return nil, err
				}
			}
			f.dirty = false
			return records, nil
		}
		if err != nil {
			return nil, err
		}
		record, decodeErr := decodeRecord(line)
		if oversize {
			decodeErr = errors.New("journal record exceeds limit")
		}
		if decodeErr != nil {
			// A torn write may include its newline. Only the final invalid
			// record is recoverable; corruption before another line is fatal.
			if _, peekErr := r.Peek(1); peekErr != io.EOF {
				return nil, decodeErr
			}
			if err := file.Truncate(offset); err != nil {
				return nil, err
			}
			if err := file.Sync(); err != nil {
				return nil, err
			}
			f.dirty = false
			return records, nil
		}
		records = append(records, record)
		offset += int64(len(line))
	}
}

func decodeRecord(line []byte) (Record, error) {
	var e envelope
	d := json.NewDecoder(bytes.NewReader(line))
	d.DisallowUnknownFields()
	if err := d.Decode(&e); err != nil {
		return Record{}, err
	}
	if err := d.Decode(new(any)); err != io.EOF {
		return Record{}, errors.New("trailing journal data")
	}
	sum := sha256.Sum256(e.Record)
	if e.Hash != hex.EncodeToString(sum[:]) {
		return Record{}, errors.New("journal checksum mismatch")
	}
	var record Record
	d = json.NewDecoder(bytes.NewReader(e.Record))
	d.DisallowUnknownFields()
	if err := d.Decode(&record); err != nil {
		return Record{}, err
	}
	return record, nil
}

func (f *FileStore) Append(record Record) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.dirty {
		return errors.New("journal needs tail recovery")
	}
	if f.SyncParent == nil {
		return errors.New("journal directory durability hook required")
	}
	raw, err := json.Marshal(record)
	if err != nil {
		return err
	}
	sum := sha256.Sum256(raw)
	line, err := json.Marshal(envelope{Record: raw, Hash: hex.EncodeToString(sum[:])})
	if err != nil {
		return err
	}
	line = append(line, '\n')
	if len(line) > RecordLimit {
		return errors.New("journal record exceeds limit")
	}
	file, err := os.OpenFile(f.Path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		return err
	}
	f.dirty = true
	n, writeErr := file.Write(line)
	if writeErr == nil && n != len(line) {
		writeErr = io.ErrShortWrite
	}
	if writeErr == nil {
		writeErr = file.Sync()
	}
	closeErr := file.Close()
	if err := errors.Join(writeErr, closeErr); err != nil {
		return err
	}
	if err := f.SyncParent(filepath.Dir(f.Path)); err != nil {
		return err
	}
	f.dirty = false
	return nil
}

// ClearRetired is used only under the engine's lifetime lock, after all
// recorded objects have been retired. Truncation is safe there: a crash leaves
// either historical removed records or an empty journal, never lost ownership.
func (f *FileStore) ClearRetired() error {
	records, err := f.Records()
	if err != nil {
		return err
	}
	live := map[string]bool{}
	for _, r := range records {
		if r.Phase == "removed" {
			delete(live, r.ID)
		} else {
			live[r.ID] = true
		}
	}
	if len(live) != 0 {
		return errors.New("cannot compact live ownership records")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	file, err := os.OpenFile(f.Path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	err = file.Sync()
	err = errors.Join(err, file.Close())
	if err != nil {
		return err
	}
	return f.SyncParent(filepath.Dir(f.Path))
}
