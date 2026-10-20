// Package lifecycle wires services, owner sessions and the control protocol.
package lifecycle

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/AyoubAchour/net-switch/internal/settings"
)

type Config struct {
	Directory string `json:"directory"`
	Data      string `json:"data"`
	Adapter   string `json:"adapter"`
	Mode      string `json:"mode"`
}
type Owner struct {
	User string `json:"user"`
	Name string `json:"name"`
}
type durableFiles struct{}

func (durableFiles) ReadFile(path string) ([]byte, error) { return os.ReadFile(path) }
func (durableFiles) WriteFile(path string, b []byte, mode os.FileMode) error {
	return writeStoreFile(path, b, mode)
}
func (durableFiles) Remove(path string) error     { return os.Remove(path) }
func (durableFiles) Rename(from, to string) error { return durableRename(from, to) }

func randomID() string {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b[:])
}
func syncFile(path string) error {
	f, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}
func Save(path string, value any) error {
	b, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	if err := settings.AtomicWrite(path, b, settings.Options{Files: durableFiles{}, SyncFile: syncFile}); err != nil {
		return err
	}
	if err := SyncDirectory(filepath.Dir(path)); err != nil {
		return err
	}
	if err := settings.AtomicWrite(path+".bak", b, settings.Options{Files: durableFiles{}, SyncFile: syncFile}); err != nil {
		return fmt.Errorf("primary saved, backup failed: %w", err)
	}
	return SyncDirectory(filepath.Dir(path))
}
func Read(path string, value any) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if len(b) > 4<<20 {
		return errors.New("state exceeds 4 MiB")
	}
	return json.Unmarshal(b, value)
}
func LoadConfig(data string) (Config, error) {
	var c Config
	if err := CheckDirectory(data); err != nil {
		return c, err
	}
	if err := Read(filepath.Join(data, "service-config.json"), &c); err != nil {
		return c, err
	}
	if c.Data != data || !filepath.IsAbs(c.Directory) || !filepath.IsAbs(c.Adapter) || (c.Mode != "proxy" && c.Mode != "tun") {
		return c, errors.New("invalid service configuration")
	}
	return c, nil
}
func LoadOwner(data string) (Owner, error) {
	var owner Owner
	err := Read(filepath.Join(data, "owner.json"), &owner)
	if os.IsNotExist(err) {
		return owner, nil
	}
	return owner, err
}
func Enroll(ctx context.Context, data, user string) (Owner, error) {
	if !Administrator() {
		return Owner{}, errors.New("owner enrolment requires an administrator")
	}
	if err := CheckDirectory(data); err != nil {
		return Owner{}, err
	}
	release, err := (Lock{Data: data, Name: "enrollment"}).Acquire(ctx)
	if err != nil {
		return Owner{}, err
	}
	defer release()
	owner, err := ResolveOwner(user)
	if err != nil {
		return Owner{}, err
	}
	if owner.User == "" || owner.User == "0" || owner.User == "S-1-5-18" {
		return Owner{}, errors.New("enrol a person, not root or SYSTEM")
	}
	if err := Save(filepath.Join(data, "owner.json"), owner); err != nil {
		return Owner{}, err
	}
	return owner, nil
}

// Migration hooks intentionally stop at validation and snapshot inspection.
// Milestone five owns the transaction that stops 0.3.x and switches packaging.
func Inspect(data string) (map[string]any, error) {
	if !Administrator() {
		return nil, errors.New("journal inspection requires an administrator")
	}
	if err := CheckDirectory(data); err != nil {
		return nil, err
	}
	out := map[string]any{}
	for _, name := range []string{"owner.json", "control-journal.json", "engine-state.json", "lifecycle.json", "migration-journal.json"} {
		var value any
		err := Read(filepath.Join(data, name), &value)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("%s: %w", name, err)
		}
		out[name] = value
	}
	if b, err := os.ReadFile(filepath.Join(data, "engine-journal.json")); err == nil {
		scan := bufio.NewScanner(bytes.NewReader(b))
		scan.Buffer(make([]byte, 4096), 1<<20)
		records := []json.RawMessage{}
		for scan.Scan() {
			if !json.Valid(scan.Bytes()) {
				return nil, errors.New("engine journal has an incomplete or damaged record; inspection did not change it")
			}
			records = append(records, append(json.RawMessage{}, scan.Bytes()...))
		}
		if err := scan.Err(); err != nil {
			return nil, err
		}
		out["engine-journal.json"] = records
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	return out, nil
}
