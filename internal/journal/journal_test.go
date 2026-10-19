package journal

import (
	"context"
	"errors"
	"maps"
	"sync"
	"testing"
	"time"
)

var crash = errors.New("simulated crash")

type steps struct{ at, n int }

func (s *steps) hit() error {
	s.n++
	if s.at == s.n {
		return crash
	}
	return nil
}

type memoryStore struct {
	records []Record
	steps   *steps
}

func (m *memoryStore) Records() ([]Record, error) { return append([]Record(nil), m.records...), nil }
func (m *memoryStore) Append(r Record) error {
	if err := m.steps.hit(); err != nil {
		return err
	}
	r.Fingerprint = maps.Clone(r.Fingerprint)
	m.records = append(m.records, r)
	return m.steps.hit()
}

type locker struct {
	once sync.Once
	held chan struct{}
}

func (l *locker) Acquire(ctx context.Context) (func() error, error) {
	l.once.Do(func() { l.held = make(chan struct{}, 1) })
	select {
	case l.held <- struct{}{}:
		return func() error { <-l.held; return nil }, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

type object struct {
	live    Fingerprint
	steps   *steps
	removed int
}

func (*object) Validate(fp Fingerprint) error {
	for _, key := range []string{"table", "priority", "destination", "gateway", "interface", "guid"} {
		if fp[key] == "" {
			return errors.New("incomplete fingerprint")
		}
	}
	return nil
}
func (o *object) Inspect(context.Context, Fingerprint) (Fingerprint, bool, error) {
	return maps.Clone(o.live), o.live != nil, nil
}
func (o *object) Create(_ context.Context, fp Fingerprint) error {
	if err := o.steps.hit(); err != nil {
		return err
	}
	o.live = maps.Clone(fp)
	return o.steps.hit()
}
func (o *object) Remove(_ context.Context, fp Fingerprint) error {
	if err := o.steps.hit(); err != nil {
		return err
	}
	if !maps.Equal(o.live, fp) {
		return errors.New("fingerprint changed before removal")
	}
	o.live = nil
	o.removed++
	return o.steps.hit()
}
func fingerprint() Fingerprint {
	return Fingerprint{"table": "21001", "priority": "10001", "destination": "0.0.0.0/0", "gateway": "192.0.2.1", "interface": "7", "guid": "unique-owner"}
}

func (o *object) Replace(ctx context.Context, before, after Fingerprint) error {
	if err := o.steps.hit(); err != nil {
		return err
	}
	if !maps.Equal(o.live, before) {
		return errors.New("replacement fingerprint changed")
	}
	o.live = maps.Clone(after)
	return o.steps.hit()
}

func TestReplacementCrashAtEveryStep(t *testing.T) {
	for at := 1; at <= 8; at++ {
		t.Run(string(rune('A'+at-1)), func(t *testing.T) {
			steps := &steps{}
			obj := &object{steps: steps}
			store := &memoryStore{steps: steps}
			j := &Journal{Store: store, Lock: &locker{}, Kinds: map[string]Object{"route": obj}}
			s, err := j.Open(context.Background(), "boot", "instance")
			if err != nil {
				t.Fatal(err)
			}
			before := fingerprint()
			after := maps.Clone(before)
			after["gateway"] = "192.0.2.99"
			if err := s.Create(context.Background(), "route", before); err != nil {
				t.Fatal(err)
			}
			steps.n = 0
			steps.at = at
			if err := s.Replace(context.Background(), "route", before, after); !errors.Is(err, crash) {
				t.Fatalf("step %d did not crash: %v", at, err)
			}
			s.Close()
			steps.at = 0
			if err := j.Cleanup(context.Background()); err != nil {
				t.Fatal(err)
			}
			if obj.live != nil {
				t.Fatalf("replacement left owned route after step %d", at)
			}
			if err := j.Cleanup(context.Background()); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestCrashAtEveryStep(t *testing.T) {
	for at := 1; at <= 10; at++ {
		t.Run(string(rune('A'+at-1)), func(t *testing.T) {
			st := &steps{at: at}
			store := &memoryStore{steps: st}
			obj := &object{steps: st}
			j := &Journal{Store: store, Lock: &locker{}, Kinds: map[string]Object{"route": obj}}
			session, err := j.Open(context.Background(), "boot", "engine")
			if err != nil {
				t.Fatal(err)
			}
			err = session.Create(context.Background(), "route", fingerprint())
			if err == nil {
				err = session.Cleanup(context.Background())
			}
			if !errors.Is(err, crash) {
				t.Fatalf("step %d did not crash: %v (%d steps)", at, err, st.n)
			}
			session.Close()
			st.at = 0
			if err := j.Cleanup(context.Background()); err != nil {
				t.Fatal(err)
			}
			if obj.live != nil {
				t.Fatal("owned object leaked")
			}
			live, err := j.live()
			if err != nil || len(live) != 0 {
				t.Fatal("journal did not recover", err)
			}
		})
	}
}
func TestNeverDeleteReplacementOrPreexisting(t *testing.T) {
	st := &steps{}
	obj := &object{steps: st}
	j := &Journal{Store: &memoryStore{steps: st}, Lock: &locker{}, Kinds: map[string]Object{"route": obj}}
	s, err := j.Open(context.Background(), "boot", "engine")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	fp := fingerprint()
	if err := s.Create(context.Background(), "route", fp); err != nil {
		t.Fatal(err)
	}
	obj.live["guid"] = "someone else"
	if err := s.Cleanup(context.Background()); err != nil {
		t.Fatal(err)
	}
	if obj.removed != 0 || obj.live == nil {
		t.Fatal("deleted replacement by name or index")
	}
	if err := s.Create(context.Background(), "route", fp); err == nil {
		t.Fatal("claimed preexisting object")
	}
}
func TestCleanupWaitsForLiveSession(t *testing.T) {
	st := &steps{}
	j := &Journal{Store: &memoryStore{steps: st}, Lock: &locker{}, Kinds: map[string]Object{}}
	s, err := j.Open(context.Background(), "boot", "engine")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if err := j.Cleanup(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("cleanup entered live engine", err)
	}
	s.Close()
	if err := j.Cleanup(context.Background()); err != nil {
		t.Fatal(err)
	}
}
func TestNoMutationBeforeDurableIntent(t *testing.T) {
	st := &steps{at: 1}
	obj := &object{steps: st}
	store := &memoryStore{steps: st}
	j := &Journal{Store: store, Lock: &locker{}, Kinds: map[string]Object{"route": obj}}
	s, _ := j.Open(context.Background(), "boot", "engine")
	defer s.Close()
	if err := s.Create(context.Background(), "route", fingerprint()); err == nil || obj.live != nil || len(store.records) != 0 {
		t.Fatal("mutation preceded durable intent")
	}
}
