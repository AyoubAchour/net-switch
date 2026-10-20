package journal

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"testing"
)

type batchMemoryStore struct {
	records []Record
	steps   *steps
	syncs   int
}

func (s *batchMemoryStore) Records() ([]Record, error) {
	return append([]Record(nil), s.records...), nil
}
func (s *batchMemoryStore) Append(r Record) error { return s.AppendBatch([]Record{r}) }
func (s *batchMemoryStore) AppendBatch(records []Record) error {
	if err := s.steps.hit(); err != nil { // before writing the batch
		return err
	}
	if err := s.steps.hit(); err != nil { // torn frame, before its durability fence
		return err
	}
	for _, record := range records {
		record.Fingerprint = maps.Clone(record.Fingerprint)
		s.records = append(s.records, record)
	}
	s.syncs++
	return s.steps.hit() // durable, but caller may never observe success
}

type checkedBatchObject struct {
	*object
	store *batchMemoryStore
}

func (o checkedBatchObject) Create(ctx context.Context, fp Fingerprint) error {
	intents := 0
	for _, r := range o.store.records {
		if r.Phase == "intent" {
			intents++
		}
	}
	if intents != 3 {
		return errors.New("mutation preceded the full durable intent batch")
	}
	return o.object.Create(ctx, fp)
}

func TestBatchCrashAtEveryDurabilityAndMutationBoundary(t *testing.T) {
	// Intent frame: 3 boundaries; three creates: 6; created frame: 3;
	// three removes: 6; removed frame: 3. The ordinary successful run is 22.
	for at := 1; at <= 22; at++ {
		t.Run(fmt.Sprint(at), func(t *testing.T) {
			st := &steps{at: at}
			store := &batchMemoryStore{steps: st}
			j := &Journal{Store: store, Lock: &locker{}, Kinds: map[string]Object{}}
			var objects []*object
			var creations []Creation
			for i := range 3 {
				kind := fmt.Sprintf("route%d", i)
				obj := &object{steps: st}
				objects = append(objects, obj)
				j.Kinds[kind] = checkedBatchObject{obj, store}
				creations = append(creations, Creation{Kind: kind, Fingerprint: fingerprint()})
			}
			session, err := j.Open(context.Background(), "boot", "engine")
			if err != nil {
				t.Fatal(err)
			}
			err = session.CreateBatch(context.Background(), creations)
			if err == nil {
				err = session.Cleanup(context.Background())
			}
			if at <= 21 && !errors.Is(err, crash) {
				t.Fatalf("boundary %d did not crash: %v (%d steps)", at, err, st.n)
			}
			if at == 22 && (err != nil || store.syncs != 3) {
				t.Fatalf("successful setup/teardown did not use three group commits: %d, %v", store.syncs, err)
			}
			session.Close()
			st.at = 0
			before, alreadyRemoved := 0, 0
			for _, obj := range objects {
				if obj.live != nil {
					before++
				}
				alreadyRemoved += obj.removed
			}
			if err := j.Cleanup(context.Background()); err != nil {
				t.Fatal(err)
			}
			removed := 0
			for _, obj := range objects {
				if obj.live != nil {
					t.Fatal("batch recovery left an owned object")
				}
				removed += obj.removed
			}
			if removed-alreadyRemoved != before {
				t.Fatalf("recovery did not remove exactly its starting leftovers: before=%d removed=%d", before, removed-alreadyRemoved)
			}
			live, err := j.live()
			if err != nil || len(live) != 0 {
				t.Fatal("batch marks did not recover", live, err)
			}
			if err := j.Cleanup(context.Background()); err != nil {
				t.Fatal("second recovery was not idempotent", err)
			}
		})
	}
}

func TestBatchChecksAllPreconditionsBeforeAnyMutation(t *testing.T) {
	st := &steps{}
	store := &batchMemoryStore{steps: st}
	free, foreign := &object{steps: st}, &object{steps: st, live: fingerprint()}
	j := &Journal{Store: store, Lock: &locker{}, Kinds: map[string]Object{"free": free, "foreign": foreign}}
	s, err := j.Open(context.Background(), "boot", "engine")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err := s.CreateBatch(context.Background(), []Creation{{"free", fingerprint()}, {"foreign", fingerprint()}}); err == nil {
		t.Fatal("batch adopted a preexisting object")
	}
	if free.live != nil || foreign.live == nil || len(store.records) != 0 {
		t.Fatal("preflight failure mutated an object or persisted ownership")
	}
	if err := s.CreateBatch(context.Background(), []Creation{{"free", fingerprint()}, {"free", fingerprint()}}); err == nil {
		t.Fatal("duplicate batch object was accepted")
	}
}

func TestBatchRecoveryKeepsAReplacement(t *testing.T) {
	st := &steps{}
	store := &batchMemoryStore{steps: st}
	obj := &object{steps: st}
	j := &Journal{Store: store, Lock: &locker{}, Kinds: map[string]Object{"route": obj}}
	s, err := j.Open(context.Background(), "boot", "engine")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.CreateBatch(context.Background(), []Creation{{"route", fingerprint()}}); err != nil {
		t.Fatal(err)
	}
	obj.live["guid"] = "replacement"
	s.Close()
	if err := j.Cleanup(context.Background()); err != nil || obj.live == nil || obj.removed != 0 {
		t.Fatal("batch recovery deleted a replacement", err)
	}
}

func TestFileBatchUsesOneSyncAndRecoversEveryTornFrame(t *testing.T) {
	path := filepath.Join(t.TempDir(), "journal")
	syncs := 0
	store := &FileStore{Path: path, SyncParent: func(string) error { syncs++; return nil }}
	old := Record{ID: "legacy", Boot: "boot", Instance: "engine", Kind: "route", Phase: "intent", Fingerprint: fingerprint()}
	if err := store.Append(old); err != nil {
		t.Fatal(err)
	}
	var batch []Record
	for i := range 3 {
		r := old
		r.ID = fmt.Sprintf("batch-%d", i)
		batch = append(batch, r)
	}
	if err := store.AppendBatch(batch); err != nil || syncs != 2 {
		t.Fatalf("three-record batch must perform one durability fence: syncs=%d err=%v", syncs, err)
	}
	if records, err := store.Records(); err != nil || len(records) != 4 {
		t.Fatal("legacy and batch frames did not coexist", records, err)
	}
	prefix, _ := encodeRecords([]Record{old})
	frame, _ := encodeRecords(batch)
	for cut := 0; cut < len(frame); cut++ {
		torn := append(append([]byte(nil), prefix...), frame[:cut]...)
		if err := os.WriteFile(path, torn, 0600); err != nil {
			t.Fatal(err)
		}
		records, err := store.Records()
		if err != nil || len(records) != 1 || records[0].ID != "legacy" {
			t.Fatalf("torn batch offset %d was partly accepted or damaged its durable prefix: %v %v", cut, records, err)
		}
	}
	// A full-sized but damaged final frame is also discarded as one unit.
	broken := append([]byte(nil), frame...)
	broken[len(broken)/2] ^= 1
	if err := os.WriteFile(path, append(prefix, broken...), 0600); err != nil {
		t.Fatal(err)
	}
	if records, err := store.Records(); err != nil || len(records) != 1 {
		t.Fatal("damaged final batch was not discarded", records, err)
	}
	// A subsequent valid frame makes this interior corruption, never a tail.
	if err := os.WriteFile(path, append(append(prefix, broken...), frame...), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Records(); err == nil {
		t.Fatal("interior batch corruption was silently discarded")
	}
	t.Logf("checked every one of %d torn batch byte boundaries", len(frame))
}
