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
	"sort"
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
type Locker interface {
	Acquire(context.Context) (release func() error, err error)
}
type Object interface {
	Validate(Fingerprint) error
	Inspect(context.Context, Fingerprint) (live Fingerprint, found bool, err error)
	Create(context.Context, Fingerprint) error
	Remove(context.Context, Fingerprint) error
}

type Replacer interface {
	Replace(context.Context, Fingerprint, Fingerprint) error
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
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.failed {
		return errors.New("journal session closed or requires recovery")
	}
	driver := s.j.Kinds[kind]
	if driver == nil {
		return fmt.Errorf("unknown journal object kind %q", kind)
	}
	fp := maps.Clone(fingerprint)
	if err := driver.Validate(fp); err != nil {
		return err
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
	r := Record{ID: hex.EncodeToString(id[:]), Boot: s.boot, Instance: s.instance, Kind: kind, Fingerprint: fp, Phase: "intent"}
	if err := s.j.Store.Append(r); err != nil {
		s.failed = true
		return fmt.Errorf("persist %s intent: %w", kind, err)
	}
	if err := driver.Create(ctx, maps.Clone(fp)); err != nil {
		s.failed = true
		return fmt.Errorf("create %s: %w", kind, err)
	}
	r.Phase = "created"
	if err := s.j.Store.Append(r); err != nil {
		s.failed = true
		return fmt.Errorf("persist %s created mark: %w", kind, err)
	}
	return nil
}

// Cleanup checks the live object again immediately before deletion. Drivers
// must also compare the supplied complete fingerprint inside Remove.
func (s *Session) Cleanup(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return errors.New("journal session closed")
	}
	records, err := s.j.live()
	if err != nil {
		return err
	}
	// Some platforms must remove selectors before the routes they select,
	// even when reconciliation appended newer routes after capture began.
	priority := func(r Record) int {
		if d, ok := s.j.Kinds[r.Kind].(interface{ CleanupPriority() int }); ok {
			return d.CleanupPriority()
		}
		return 0
	}
	sort.SliceStable(records, func(i, j int) bool { return priority(records[i]) > priority(records[j]) })
	for i := len(records) - 1; i >= 0; i-- {
		r := records[i]
		driver := s.j.Kinds[r.Kind]
		if driver == nil {
			return fmt.Errorf("cannot clean unknown object kind %q", r.Kind)
		}
		if err := driver.Validate(r.Fingerprint); err != nil {
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
		if err := s.j.Store.Append(r); err != nil {
			return err
		}
	}
	s.failed = false
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

// Remove retires one owned object during reconciliation, with the same
// fingerprint check as shutdown. It never claims a replacement object.
func (s *Session) Remove(ctx context.Context, kind string, fp Fingerprint) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return errors.New("journal session closed")
	}
	records, err := s.j.live()
	if err != nil {
		return err
	}
	for i := len(records) - 1; i >= 0; i-- {
		r := records[i]
		if r.Kind != kind || !maps.Equal(r.Fingerprint, fp) {
			continue
		}
		d := s.j.Kinds[kind]
		live, found, err := d.Inspect(ctx, maps.Clone(fp))
		if err != nil {
			return err
		}
		if found && maps.Equal(live, fp) {
			if err := d.Remove(ctx, maps.Clone(fp)); err != nil {
				return err
			}
		}
		r.Phase = "removed"
		return s.j.Store.Append(r)
	}
	return nil
}

// Replace preserves a live route while changing its gateway or attributes.
// Both fingerprints remain recoverable if the process exits at any step.
func (s *Session) Replace(ctx context.Context, kind string, before, after Fingerprint) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.failed {
		return errors.New("journal session closed or requires recovery")
	}
	d := s.j.Kinds[kind]
	replacer, ok := d.(Replacer)
	if !ok {
		return errors.New("object has no atomic replacement operation")
	}
	if err := d.Validate(after); err != nil {
		return err
	}
	records, err := s.j.live()
	if err != nil {
		return err
	}
	var previous *Record
	for i := range records {
		if records[i].Kind == kind && maps.Equal(records[i].Fingerprint, before) {
			r := records[i]
			previous = &r
			break
		}
	}
	if previous == nil {
		return errors.New("replacement has no owned original")
	}
	live, found, err := d.Inspect(ctx, maps.Clone(before))
	if err != nil {
		return err
	}
	if !found || !maps.Equal(live, before) {
		return errors.New("original changed before replacement")
	}
	var id [16]byte
	if _, err := rand.Read(id[:]); err != nil {
		return err
	}
	next := Record{ID: hex.EncodeToString(id[:]), Boot: s.boot, Instance: s.instance, Kind: kind, Fingerprint: maps.Clone(after), Phase: "intent"}
	fail := func(err error) error { s.failed = true; return err }
	if err := s.j.Store.Append(next); err != nil {
		return fail(err)
	}
	if err := replacer.Replace(ctx, maps.Clone(before), maps.Clone(after)); err != nil {
		return fail(err)
	}
	next.Phase = "created"
	if err := s.j.Store.Append(next); err != nil {
		return fail(err)
	}
	previous.Phase = "removed"
	if err := s.j.Store.Append(*previous); err != nil {
		return fail(err)
	}
	return nil
}
func (j *Journal) Cleanup(ctx context.Context) error {
	s, err := j.Open(ctx, "cleanup", "cleanup")
	if err != nil {
		return err
	}
	defer s.Close()
	return s.Cleanup(ctx)
}
