package host

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sync"

	"github.com/AyoubAchour/net-switch/internal/engine/policy"
)

// Record is historical state, never a loaded policy. A point is meaningful only
// in a live table, so it is deliberately absent from the durable representation.
type Record struct {
	Schema   int    `json:"schema"`
	Instance string `json:"engineInstanceId"`
	Epoch    uint64 `json:"epoch"`
	N        uint64 `json:"n"`
	Hash     string `json:"hash"`
}

// Durable serializes epoch and revision commits into one record. Its caller
// owns directory validation, the lifetime lock, and atomic durable replacement.
type Durable struct {
	mu     sync.Mutex
	record Record
	save   func(Record) error
}

func Open(path, instance string, save func(Record) error) (*Durable, error) {
	if instance == "" || save == nil {
		return nil, errors.New("native state requires an instance and durable writer")
	}
	var old Record
	file, err := os.Open(path)
	if err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	if err == nil {
		b, readErr := io.ReadAll(io.LimitReader(file, (16<<10)+1))
		closeErr := file.Close()
		if err := errors.Join(readErr, closeErr); err != nil {
			return nil, err
		}
		if len(b) > 16<<10 {
			return nil, errors.New("native service state exceeds its bound")
		}
		if err := json.Unmarshal(b, &old); err != nil {
			return nil, fmt.Errorf("invalid native service state: %w", err)
		}
		// A stand-in state must be retired by the migration path, never read
		// as a fresh native instance or silently reset to epoch zero.
		if old.Schema != 1 {
			return nil, errors.New("native service state schema is not supported")
		}
	}
	next := old
	next.Schema, next.Instance = 1, instance
	if err := save(next); err != nil {
		return nil, err
	}
	return &Durable{record: next, save: save}, nil
}

func (d *Durable) InitialEpoch() uint64 {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.record.Epoch
}

func (d *Durable) SaveEpoch(epoch uint64) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if epoch <= d.record.Epoch {
		return errors.New("native epoch must increase")
	}
	next := d.record
	next.Epoch = epoch
	if err := d.save(next); err != nil {
		return err
	}
	d.record = next
	return nil
}

func (d *Durable) SaveApplied(a policy.Applied) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	next := d.record
	next.N, next.Hash = a.N, a.Hash
	if err := d.save(next); err != nil {
		return err
	}
	d.record = next
	return nil
}
