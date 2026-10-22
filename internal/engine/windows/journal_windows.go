//go:build windows

package winengine

import (
	"errors"
	"os"
	"path/filepath"
	"sync"

	"github.com/AyoubAchour/net-switch/internal/journal"
	"golang.org/x/sys/windows"
)

// The lifetime ownership mutex excludes other processes. This mutex also keeps
// direct store users from appending while an atomic checkpoint is installed.
type diskJournal struct {
	mu      sync.Mutex
	file    *journal.FileStore
	sync    func(*os.File) error
	replace func(string, string) error
}

func newDiskJournal(path string) *diskJournal {
	return &diskJournal{file: &journal.FileStore{Path: path, SyncParent: SyncParent},
		sync: (*os.File).Sync, replace: replaceJournal}
}

func replaceJournal(from, to string) error {
	source, err := windows.UTF16PtrFromString(from)
	if err != nil {
		return err
	}
	destination, err := windows.UTF16PtrFromString(to)
	if err != nil {
		return err
	}
	// Both names are in the same private directory/volume. Write-through waits
	// for the rename's durability as well as the already-flushed file contents.
	return windows.MoveFileEx(source, destination, windows.MOVEFILE_REPLACE_EXISTING|windows.MOVEFILE_WRITE_THROUGH)
}

func (s *diskJournal) Records() ([]journal.Record, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.file.Records()
}
func (s *diskJournal) Append(record journal.Record) error {
	return s.AppendBatch([]journal.Record{record})
}
func (s *diskJournal) AppendBatch(records []journal.Record) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.file.AppendBatch(records)
}
func (s *diskJournal) Compact(records []journal.Record) (err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	path := s.file.Path
	if len(records) == 0 {
		info, statErr := os.Stat(path)
		if errors.Is(statErr, os.ErrNotExist) || (statErr == nil && info.Size() == 0) {
			s.file = &journal.FileStore{Path: path, SyncParent: SyncParent}
			return nil
		}
		if statErr != nil {
			return statErr
		}
	}
	temp, err := os.CreateTemp(filepath.Dir(path), ".engine-journal-checkpoint-")
	if err != nil {
		return err
	}
	name := temp.Name()
	defer os.Remove(name) // After a successful rename this name no longer exists.
	if len(records) == 0 {
		err = s.sync(temp)
	} // Nonempty checkpoints use the shared checksummed format and its sync.
	err = errors.Join(err, temp.Close())
	if err != nil {
		return err
	}
	if len(records) != 0 {
		// A compacted created object still needs its matching intent when
		// decoded by the shared journal state machine.
		checkpointRecords := make([]journal.Record, 0, 2*len(records))
		for _, record := range records {
			phase := record.Phase
			if phase != "intent" && phase != "created" {
				return errors.New("checkpoint contains a non-live record")
			}
			record.Phase = "intent"
			checkpointRecords = append(checkpointRecords, record)
			if phase == "created" {
				record.Phase = "created"
				checkpointRecords = append(checkpointRecords, record)
			}
		}
		checkpoint := &journal.FileStore{Path: name, SyncParent: SyncParent}
		if err := checkpoint.AppendBatch(checkpointRecords); err != nil {
			return err
		}
	}
	if err := s.replace(name, path); err != nil {
		return err
	}
	s.file = &journal.FileStore{Path: path, SyncParent: SyncParent}
	return nil
}

var _ journal.Compactor = (*diskJournal)(nil)

// Only stores with a real atomic replacement expose Compactor. The ordinary
// measured wrapper retains grouped removed marks for legacy/noncompact stores.
type compactingJournalStore struct{ measuredJournalStore }

func (s compactingJournalStore) Compact(records []journal.Record) error {
	if s.beforeRemoved != nil {
		if err := s.beforeRemoved(); err != nil {
			return err
		}
	}
	defer s.timings.begin("journal.compact")()
	return s.Store.(journal.Compactor).Compact(records)
}
