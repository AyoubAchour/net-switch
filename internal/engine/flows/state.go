package flows

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"

	"github.com/AyoubAchour/net-switch/internal/engine/policy"
)

// FileState is history only. New Table instances intentionally never load it
// as active policy. The platform supplies directory durability and parent ACLs.
type FileState struct {
	Path       string
	SyncParent func(string) error
}

func (f FileState) SaveApplied(a policy.Applied) error {
	if f.SyncParent == nil {
		return errors.New("state directory durability hook required")
	}
	file, err := os.CreateTemp(filepath.Dir(f.Path), ".engine-state-")
	if err != nil {
		return err
	}
	name := file.Name()
	defer os.Remove(name)
	if err := json.NewEncoder(file).Encode(a); err != nil {
		file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if err := os.Rename(name, f.Path); err != nil {
		return err
	}
	return f.SyncParent(filepath.Dir(f.Path))
}
func (f FileState) History() (*policy.Applied, error) {
	file, err := os.Open(f.Path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer file.Close()
	var a policy.Applied
	d := json.NewDecoder(file)
	d.DisallowUnknownFields()
	if err := d.Decode(&a); err != nil {
		return nil, err
	}
	return &a, nil
}
