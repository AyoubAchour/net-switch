package settings

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/AyoubAchour/net-switch/internal/apps"
	js "github.com/AyoubAchour/net-switch/internal/jsvalue"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

type Files interface {
	ReadFile(string) ([]byte, error)
	WriteFile(string, []byte, fs.FileMode) error
	Rename(string, string) error
	Remove(string) error
}
type disk struct{}

func (disk) ReadFile(p string) ([]byte, error)                 { return os.ReadFile(p) }
func (disk) WriteFile(p string, b []byte, m fs.FileMode) error { return os.WriteFile(p, b, m) }
func (disk) Rename(a, b string) error                          { return os.Rename(a, b) }
func (disk) Remove(p string) error                             { return os.Remove(p) }

type Options struct {
	FileName      string
	Defaults      map[string]any
	DefaultKeys   []string // Optional insertion order for a custom defaults object.
	Files         Files
	Now           func() time.Time
	ID            func() string
	Sleep         func(time.Duration)
	OnBackupError func(error)
	// SyncFile is used by the control recovery journal. Other settings keep
	// their legacy write behavior. It runs before the atomic rename.
	SyncFile func(string) error
	// SyncParent makes an acknowledged rename durable across an OS restart.
	// Service journals supply it; legacy behavior-port callers leave it nil.
	SyncParent func(string) error
}
type Recovery struct {
	Reason     string  `json:"reason"`
	SavedAs    *string `json:"savedAs"`
	UsedBackup bool    `json:"usedBackup"`
}
type Store struct {
	mu       sync.Mutex
	File     string
	defaults map[string]any
	values   map[string]json.RawMessage
	Recovery *Recovery
	options  Options
}

func defaults() map[string]any {
	return map[string]any{"lines": []any{}, "appLines": apps.Pins{}, "combine": false, "combineMode": "auto", "probeTargets": []any{"1.1.1.1:443", "8.8.8.8:443"}, "ipv6": "auto", "checkForUpdates": true, "skippedUpdate": nil}
}
func id() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b[:])
}
func New(dir string, o Options) *Store {
	if o.FileName == "" {
		o.FileName = "settings.json"
	}
	if o.Defaults == nil {
		o.Defaults = defaults()
		o.DefaultKeys = []string{"lines", "appLines", "combine", "combineMode", "probeTargets", "ipv6", "checkForUpdates", "skippedUpdate"}
	}
	seen := map[string]bool{}
	for _, key := range o.DefaultKeys {
		seen[key] = true
	}
	remaining := []string{}
	for key := range o.Defaults {
		if !seen[key] {
			remaining = append(remaining, key)
		}
	}
	sort.Strings(remaining)
	o.DefaultKeys = append(append([]string{}, o.DefaultKeys...), remaining...)
	if o.Files == nil {
		o.Files = disk{}
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.ID == nil {
		o.ID = id
	}
	if o.Sleep == nil {
		o.Sleep = time.Sleep
	}
	s := &Store{File: filepath.Join(dir, o.FileName), defaults: clone(o.Defaults), options: o}
	s.values = raw(s.defaults)
	return s
}
func clone(m map[string]any) map[string]any {
	return decode(raw(m))
}
func raw(m map[string]any) map[string]json.RawMessage {
	out := map[string]json.RawMessage{}
	for k, v := range m {
		out[k], _ = js.Marshal(v)
	}
	return out
}
func decode(m map[string]json.RawMessage) map[string]any {
	out := map[string]any{}
	for k, v := range m {
		x, _ := js.Decode(v)
		if k == "appLines" {
			if p, err := apps.ParsePins(v); err == nil {
				x = p
			}
		}
		out[k] = x
	}
	return out
}
func (s *Store) Values() map[string]any { s.mu.Lock(); defer s.mu.Unlock(); return decode(s.values) }
func (s *Store) RawValues() map[string]json.RawMessage {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := map[string]json.RawMessage{}
	for k, v := range s.values {
		out[k] = bytes.Clone(v)
	}
	return out
}

type invalidJSON struct{ error }

func parse(b []byte) (map[string]json.RawMessage, error) {
	var value any
	d := json.NewDecoder(bytes.NewReader(b))
	d.UseNumber()
	if err := d.Decode(&value); err != nil {
		return nil, invalidJSON{err}
	}
	if _, ok := value.(map[string]any); !ok {
		return nil, invalidJSON{errors.New("The JSON value is not a plain object.")}
	}
	var result map[string]json.RawMessage
	err := json.Unmarshal(b, &result)
	if err != nil {
		return nil, invalidJSON{err}
	}
	return result, err
}
func valid(value, fallback any) bool {
	switch def := fallback.(type) {
	case nil, string:
		_, ok := value.(string)
		return value == nil || ok
	case []any:
		items, ok := value.([]any)
		if !ok {
			return false
		}
		for _, item := range items {
			if len(def) == 0 {
				if _, ok := item.(map[string]any); !ok {
					return false
				}
			} else {
				if _, ok := item.(string); !ok {
					return false
				}
			}
		}
		return true
	case map[string]any:
		_, ok := value.(map[string]any)
		return ok
	case apps.Pins:
		_, ok := value.(map[string]any)
		return ok
	case float64:
		return js.Finite(value)
	case bool:
		_, ok := value.(bool)
		return ok
	}
	return false
}
func (s *Store) Load() (map[string]any, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Recovery = nil
	data, err := s.options.Files.ReadFile(s.File)
	var saved map[string]json.RawMessage
	if err == nil {
		saved, err = parse(data)
	}
	if err != nil {
		var invalid invalidJSON
		if errors.As(err, &invalid) {
			stamp := s.options.Now().UTC().Format("2006-01-02T15-04-05.000Z")
			stamp = strings.ReplaceAll(stamp, ".", "-")
			name := s.File + ".corrupt-" + stamp + "-" + s.options.ID()
			if copyErr := s.options.Files.WriteFile(name, data, 0600); copyErr != nil {
				return nil, copyErr
			}
			s.Recovery = &Recovery{Reason: "Invalid settings: " + err.Error(), SavedAs: &name}
			backup, backupErr := s.options.Files.ReadFile(s.File + ".bak")
			if backupErr == nil {
				saved, backupErr = parse(backup)
			}
			if backupErr == nil {
				s.Recovery.UsedBackup = true
			} else if errors.As(backupErr, &invalid) || errors.Is(backupErr, fs.ErrNotExist) {
				s.Recovery.Reason += " Backup unavailable: " + backupErr.Error()
			} else {
				return nil, backupErr
			}
		} else if !errors.Is(err, fs.ErrNotExist) {
			return nil, err
		}
	}
	values := raw(s.defaults)
	for k, v := range saved {
		values[k] = v
	}
	invalidKeys := []string{}
	for _, k := range s.options.DefaultKeys {
		fallback := s.defaults[k]
		if encoded, ok := saved[k]; ok {
			v, _ := js.Decode(encoded)
			if !valid(v, fallback) {
				values[k], _ = js.Marshal(fallback)
				invalidKeys = append(invalidKeys, k)
			}
		}
	}
	if len(invalidKeys) > 0 {
		if s.Recovery == nil {
			s.Recovery = &Recovery{}
		}
		if s.Recovery.Reason != "" {
			s.Recovery.Reason += " "
		}
		s.Recovery.Reason += "Invalid types reset to defaults: " + strings.Join(invalidKeys, ", ") + "."
	}
	delete(values, "boost")
	delete(values, "boostTrustSince")
	s.values = values
	return decode(values), nil
}

// Delete represents a Node undefined property in an update; null remains JSON null.
var Delete = struct{}{}

func (s *Store) Update(changes map[string]any) (map[string]any, error) {
	return s.Change(func(map[string]any) map[string]any { return changes })
}
func (s *Store) Change(change func(map[string]any) map[string]any) (map[string]any, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	next := map[string]json.RawMessage{}
	for k, v := range s.values {
		next[k] = v
	}
	for k, v := range change(decode(s.values)) {
		if _, ok := v.(struct{}); ok {
			delete(next, k)
			continue
		}
		// A map cannot express saved app priority. Require ordered pins (or raw
		// JSON), so a future caller cannot silently sort away a user's choice.
		if k == "appLines" {
			switch v.(type) {
			case apps.Pins, json.RawMessage:
			default:
				return nil, errors.New("appLines updates require apps.Pins or ordered JSON")
			}
		}
		b, err := js.Marshal(v)
		if err != nil {
			return nil, err
		}
		next[k] = b
	}
	var buffer bytes.Buffer
	encoder := json.NewEncoder(&buffer)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(next); err != nil {
		return nil, err
	}
	text := bytes.TrimSuffix(buffer.Bytes(), []byte("\n"))
	if err := AtomicWrite(s.File, text, s.options); err != nil {
		return nil, err
	}
	s.values = next
	if err := AtomicWrite(s.File+".bak", text, s.options); err != nil && s.options.OnBackupError != nil {
		func() { defer func() { _ = recover() }(); s.options.OnBackupError(err) }()
	}
	return decode(next), nil
}
func AtomicWrite(file string, text []byte, o Options) error {
	if o.Files == nil {
		o.Files = disk{}
	}
	if o.ID == nil {
		o.ID = id
	}
	if o.Sleep == nil {
		o.Sleep = time.Sleep
	}
	temp := file + "." + o.ID() + ".tmp"
	if err := o.Files.WriteFile(temp, text, 0600); err != nil {
		return err
	}
	if o.SyncFile != nil {
		if err := o.SyncFile(temp); err != nil {
			_ = o.Files.Remove(temp)
			return fmt.Errorf("sync %s: %w", file, err)
		}
	}
	for attempt := 0; ; attempt++ {
		err := o.Files.Rename(temp, file)
		if err == nil {
			if o.SyncParent != nil {
				return o.SyncParent(filepath.Dir(file))
			}
			return nil
		}
		if attempt >= 10 || !retryable(err) {
			if removeErr := o.Files.Remove(temp); removeErr != nil && !errors.Is(removeErr, fs.ErrNotExist) {
				return fmt.Errorf("rename failed: %v; temporary-file cleanup failed: %w", err, removeErr)
			}
			return err
		}
		o.Sleep(50 * time.Millisecond)
	}
}
