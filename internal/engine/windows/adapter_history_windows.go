//go:build windows

package winengine

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"

	"github.com/AyoubAchour/net-switch/internal/sharedfile"
	"github.com/AyoubAchour/net-switch/internal/wintun"
)

type adapterHistory struct {
	Boot, GUID string
	LUID       uint64
}

// Historical identity is retained across empty journal checkpoints and process
// exit. It never authorizes deletion: PnP, IP and replacement checks still run.
// Both calls are under the lifetime lock and use the validated private directory.
func (s *diskJournal) adapterHistory(boot string) (uint64, error) {
	b, err := sharedfile.ReadFile(s.file.Path+".adapter", 1024)
	if os.IsNotExist(err) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	var record adapterHistory
	if len(b) > 1024 || json.Unmarshal(b, &record) != nil || record.GUID != wintun.DefaultGUID || record.LUID == 0 || record.Boot == "" {
		return 0, errors.New("invalid adapter identity history")
	}
	if record.Boot != boot {
		return 0, nil
	}
	return record.LUID, nil
}

func (s *diskJournal) saveAdapterHistory(boot string, luid uint64) (err error) {
	b, err := json.Marshal(adapterHistory{boot, wintun.DefaultGUID, luid})
	if err != nil {
		return err
	}
	path := s.file.Path + ".adapter"
	f, err := os.CreateTemp(filepath.Dir(path), ".adapter-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	_, err = f.Write(b)
	if err == nil {
		err = s.sync(f)
	}
	err = errors.Join(err, f.Close())
	if err != nil {
		return err
	}
	return s.replace(f.Name(), path)
}
