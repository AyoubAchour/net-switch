// Package journal records ownership before OS mutations. Object drivers supply
// complete fingerprints; cleanup never infers ownership from a name or index.
package journal

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"maps"
	"sync"
)

type Fingerprint map[string]string
type Record struct {
	ID          string      `json:"id"`
	Boot        string      `json:"bootId"`
	Instance    string      `json:"engineInstanceId"`
	Kind        string      `json:"kind"`
	Fingerprint Fingerprint `json:"fingerprint"`
	Phase       string      `json:"phase"`
}

// Append returns only after the complete record is durable. Records recovers
// an incomplete tail and refuses corruption in a complete record.
type Store interface {
	Records() ([]Record, error)
	Append(Record) error
}

// BatchStore returns only after every record in the batch is durable. A failed
// append may leave a recoverable prefix, but callers must perform no mutations.
// Existing Store implementations remain valid and retain per-record durability.
type BatchStore interface {
	AppendBatch([]Record) error
}

func appendRecords(store Store, records []Record) error {
	if len(records) == 0 {
		return nil
	}
	if batch, ok := store.(BatchStore); ok {
		return batch.AppendBatch(records)
	}
	for _, record := range records {
		if err := store.Append(record); err != nil {
			return err
		}
	}
	return nil
}

type Creation struct {
	Kind        string
	Fingerprint Fingerprint
}
type Locker interface {
	Acquire(context.Context) (release func() error, err error)
}
type Object interface {
	Validate(Fingerprint) error
	Inspect(context.Context, Fingerprint) (live Fingerprint, found bool, err error)
	Create(context.Context, Fingerprint) error
	Remove(context.Context, Fingerprint) error
}
type Journal struct {
	Store Store
	Lock  Locker
	Kinds map[string]Object
}
type Session struct {
	mu             sync.Mutex
	j              *Journal
	boot, instance string
	release        func() error
	closed, failed bool
}

// Open holds the OS lock through the engine's lifetime. Cleanup in another
// process cannot delete a live engine's objects; a crash releases the OS lock.
func (j *Journal) Open(ctx context.Context, boot, instance string) (*Session, error) {
	if j.Store == nil || j.Lock == nil || boot == "" || instance == "" {
		return nil, errors.New("journal needs store, lock, boot and instance")
	}
	release, err := j.Lock.Acquire(ctx)
	if err != nil {
		return nil, err
	}
	if _, err := j.live(); err != nil {
		release()
		return nil, err
	}
	return &Session{j: j, boot: boot, instance: instance, release: release}, nil
}
func (j *Journal) live() ([]Record, error) {
	records, err := j.Store.Records()
	if err != nil {
		return nil, err
	}
	state := map[string]Record{}
	var order []string
	for _, r := range records {
		if r.ID == "" || r.Boot == "" || r.Instance == "" || r.Kind == "" || len(r.Fingerprint) == 0 {
			return nil, errors.New("invalid journal record")
		}
		old, exists := state[r.ID]
		if r.Phase == "intent" {
			if exists {
				return nil, errors.New("duplicate intent")
			}
			state[r.ID] = r
			order = append(order, r.ID)
			continue
		}
		if !exists || old.Boot != r.Boot || old.Instance != r.Instance || old.Kind != r.Kind || !maps.Equal(old.Fingerprint, r.Fingerprint) {
			return nil, errors.New("journal mark has no matching intent")
		}
		if old.Phase == "removed" || r.Phase != "created" && r.Phase != "removed" {
			return nil, errors.New("invalid journal transition")
		}
		state[r.ID] = r
	}
	var live []Record
	for _, id := range order {
		if r := state[id]; r.Phase != "removed" {
			live = append(live, r)
		}
	}
	return live, nil
}
func (s *Session) Create(ctx context.Context, kind string, fingerprint Fingerprint) error {
	return s.CreateBatch(ctx, []Creation{{Kind: kind, Fingerprint: fingerprint}})
}

// CreateBatch groups one independent setup phase. Every object must be absent
// before the phase starts; dependencies such as adapter then address use separate
// phases. All intents are durable before the first Create, and all created marks
// are durable before returning success.
func (s *Session) CreateBatch(ctx context.Context, creations []Creation) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.failed {
		return errors.New("journal session closed or requires recovery")
	}
	records := make([]Record, 0, len(creations))
	for _, creation := range creations {
		if err := ctx.Err(); err != nil {
			return err
		}
		driver := s.j.Kinds[creation.Kind]
		if driver == nil {
			return fmt.Errorf("unknown journal object kind %q", creation.Kind)
		}
		fp := maps.Clone(creation.Fingerprint)
		if err := driver.Validate(maps.Clone(fp)); err != nil {
			return err
		}
		for _, prior := range records {
			if prior.Kind == creation.Kind && maps.Equal(prior.Fingerprint, fp) {
				return errors.New("duplicate object in journal creation batch")
			}
		}
		if _, found, err := driver.Inspect(ctx, maps.Clone(fp)); err != nil {
			return err
		} else if found {
			return errors.New("object already exists; refusing to claim ownership")
		}
		var id [16]byte
		if _, err := rand.Read(id[:]); err != nil {
			return err
		}
		records = append(records, Record{ID: hex.EncodeToString(id[:]), Boot: s.boot, Instance: s.instance,
			Kind: creation.Kind, Fingerprint: fp, Phase: "intent"})
	}
	if err := appendRecords(s.j.Store, records); err != nil {
		s.failed = true
		return fmt.Errorf("persist creation intents: %w", err)
	}
	for i := range records {
		r := &records[i]
		if err := ctx.Err(); err != nil {
			s.failed = true
			return err
		}
		if err := s.j.Kinds[r.Kind].Create(ctx, maps.Clone(r.Fingerprint)); err != nil {
			s.failed = true
			return fmt.Errorf("create %s: %w", r.Kind, err)
		}
		r.Phase = "created"
	}
	if err := appendRecords(s.j.Store, records); err != nil {
		s.failed = true
		return fmt.Errorf("persist created marks: %w", err)
	}
	return nil
}

// Cleanup checks the live object again immediately before deletion. Drivers
// must also compare the supplied complete fingerprint inside Remove.
func (s *Session) Cleanup(ctx context.Context) (err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return errors.New("journal session closed")
	}
	// A failed read or validation also makes ownership uncertain. Keep Create
	// fenced until a complete recovery succeeds, including this initial read.
	s.failed = true
	records, err := s.j.live()
	if err != nil {
		return err
	}
	var removed []Record
	// A crash before or during this mark batch leaves the original intents.
	// Recovery repeats the same fingerprint checks and safely skips missing
	// objects. On a mid-cleanup error, retain marks for the completed prefix.
	defer func() {
		err = errors.Join(err, appendRecords(s.j.Store, removed))
		if err == nil {
			s.failed = false
		}
	}()
	for i := len(records) - 1; i >= 0; i-- {
		if err := ctx.Err(); err != nil {
			return err
		}
		r := records[i]
		driver := s.j.Kinds[r.Kind]
		if driver == nil {
			return fmt.Errorf("cannot clean unknown object kind %q", r.Kind)
		}
		if err := driver.Validate(maps.Clone(r.Fingerprint)); err != nil {
			return err
		}
		live, found, err := driver.Inspect(ctx, maps.Clone(r.Fingerprint))
		if err != nil {
			return err
		}
		if found && maps.Equal(live, r.Fingerprint) {
			if err := driver.Remove(ctx, maps.Clone(r.Fingerprint)); err != nil {
				return err
			}
		}
		// Missing and replaced objects no longer belong to us.
		r.Phase = "removed"
		removed = append(removed, r)
	}
	return nil
}
func (s *Session) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	return s.release()
}
func (j *Journal) Cleanup(ctx context.Context) error {
	s, err := j.Open(ctx, "cleanup", "cleanup")
	if err != nil {
		return err
	}
	defer s.Close()
	return s.Cleanup(ctx)
}
