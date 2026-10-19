package settings

import (
	"encoding/json"
	"errors"
	"github.com/AyoubAchour/net-switch/internal/apps"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

func write(t *testing.T, p, s string) {
	t.Helper()
	if err := os.WriteFile(p, []byte(s), 0600); err != nil {
		t.Fatal(err)
	}
}
func read(t *testing.T, p string) string {
	t.Helper()
	b, e := os.ReadFile(p)
	if e != nil {
		t.Fatal(e)
	}
	return string(b)
}
func load(t *testing.T, s *Store) map[string]any {
	t.Helper()
	v, e := s.Load()
	if e != nil {
		t.Fatal(e)
	}
	return v
}
func update(t *testing.T, s *Store, v map[string]any) map[string]any {
	t.Helper()
	result, e := s.Update(v)
	if e != nil {
		t.Fatal(e)
	}
	return result
}
func require(t *testing.T, condition bool) {
	t.Helper()
	if !condition {
		t.Fatal("condition failed")
	}
}
func TestSettings(t *testing.T) {
	t.Run("corrupt settings recover from the backup and keep the exact bad file", func(t *testing.T) {
		s := New(t.TempDir(), Options{})
		write(t, s.File, "{broken")
		write(t, s.File+".bak", `{"combine":true,"extra":42}`)
		v := load(t, s)
		require(t, v["combine"] == true && v["extra"] == float64(42))
		require(t, s.Recovery.UsedBackup && strings.Contains(s.Recovery.Reason, "Invalid settings"))
		require(t, strings.HasPrefix(*s.Recovery.SavedAs, s.File+".corrupt-"))
		require(t, read(t, *s.Recovery.SavedAs) == "{broken" && read(t, s.File) == "{broken")
	})
	t.Run("corrupt settings without a usable backup fall back to defaults", func(t *testing.T) {
		for _, backup := range []string{"", "{broken", "[]"} {
			s := New(t.TempDir(), Options{})
			write(t, s.File, "{broken")
			if backup != "" {
				write(t, s.File+".bak", backup)
			}
			v := load(t, s)
			require(t, reflect.DeepEqual(v, defaults()))
			require(t, !s.Recovery.UsedBackup && read(t, *s.Recovery.SavedAs) == "{broken")
		}
	})
	t.Run("JSON values other than plain objects are preserved as corrupt", func(t *testing.T) {
		for _, text := range []string{"null", "[]", "42", `"Cable"`, "true"} {
			s := New(t.TempDir(), Options{})
			write(t, s.File, text)
			v := load(t, s)
			require(t, len(v["lines"].([]any)) == 0)
			require(t, read(t, *s.Recovery.SavedAs) == text && strings.Contains(s.Recovery.Reason, "plain object"))
		}
	})
	t.Run("load repairs wrong types per key, retains unknown keys, and strips booster settings", func(t *testing.T) {
		s := New(t.TempDir(), Options{})
		write(t, s.File, `{"lines":[{"id":"a1","alias":"Ethernet"},"Wi-Fi"],"appLines":["app.exe"],"probeTargets":["1.1.1.1:443",8],"combine":"false","combineMode":"manual","extra":{"keep":true},"secondAlias":"Wi-Fi","boost":true,"boostTrustSince":"yesterday"}`)
		v := load(t, s)
		require(t, len(v["lines"].([]any)) == 0 && len(v["appLines"].(apps.Pins)) == 0)
		require(t, v["combine"] == false && v["combineMode"] == "manual" && v["secondAlias"] == "Wi-Fi")
		require(t, reflect.DeepEqual(v["extra"], map[string]any{"keep": true}))
		_, boost := v["boost"]
		_, trust := v["boostTrustSince"]
		require(t, !boost && !trust && s.Recovery.SavedAs == nil)
		for _, key := range []string{"lines", "appLines", "probeTargets", "combine"} {
			require(t, strings.Contains(s.Recovery.Reason, key))
		}
		write(t, s.File, `{"lines":[{"id":"a1","alias":"Ethernet"}]}`)
		require(t, len(load(t, s)["lines"].([]any)) == 1)
	})
	t.Run("a key updated to undefined is removed, in memory and on disk", func(t *testing.T) {
		s := New(t.TempDir(), Options{})
		update(t, s, map[string]any{"secondAlias": "Wi-Fi"})
		update(t, s, map[string]any{"secondAlias": Delete})
		_, exists := s.Values()["secondAlias"]
		require(t, !exists && !strings.Contains(read(t, s.File), "secondAlias"))
	})
	t.Run("a reusable store has its own file and defaults, and clears recovery on a clean load", func(t *testing.T) {
		dir := t.TempDir()
		s := New(dir, Options{FileName: "undo.json", Defaults: map[string]any{"count": float64(0), "name": "none", "enabled": true}})
		require(t, reflect.DeepEqual(load(t, s), s.defaults) && s.Recovery == nil)
		write(t, s.File, `{"count":"bad","name":null,"enabled":false}`)
		require(t, reflect.DeepEqual(load(t, s), map[string]any{"count": float64(0), "name": nil, "enabled": false}))
		require(t, strings.Contains(s.Recovery.Reason, "count"))
		update(t, s, map[string]any{"count": 1})
		load(t, s)
		require(t, s.Recovery == nil)
		entries, e := os.ReadDir(dir)
		require(t, e == nil && len(entries) == 2)
	})
	t.Run("concurrent updates are serialized and the backup matches the latest successful write", func(t *testing.T) {
		s := New(t.TempDir(), Options{Defaults: map[string]any{"count": 0}})
		var wg sync.WaitGroup
		results := make(chan float64, 12)
		for i := 0; i < 12; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				v, e := s.Change(func(v map[string]any) map[string]any { return map[string]any{"count": v["count"].(float64) + 1} })
				if e != nil {
					t.Error(e)
					return
				}
				results <- v["count"].(float64)
			}()
		}
		wg.Wait()
		close(results)
		seen := map[float64]bool{}
		for v := range results {
			seen[v] = true
		}
		for i := 1; i <= 12; i++ {
			require(t, seen[float64(i)])
		}
		require(t, s.Values()["count"] == float64(12))
		require(t, read(t, s.File) == read(t, s.File+".bak"))
	})
	t.Run("backup failures are reported without failing a successful update", func(t *testing.T) {
		reported := 0
		s := New(t.TempDir(), Options{Sleep: func(time.Duration) {}, OnBackupError: func(error) { reported++; panic("reporter failed") }})
		if e := os.Mkdir(s.File+".bak", 0700); e != nil {
			t.Fatal(e)
		}
		require(t, update(t, s, map[string]any{"combine": true})["combine"] == true && reported == 1)
		var v map[string]any
		if e := json.Unmarshal([]byte(read(t, s.File)), &v); e != nil {
			t.Fatal(e)
		}
		require(t, v["combine"] == true)
	})
	t.Run("a failed write leaves memory unchanged and does not block later updates", func(t *testing.T) {
		s := New(t.TempDir(), Options{Defaults: map[string]any{"count": 0}, Sleep: func(time.Duration) {}})
		if e := os.Mkdir(s.File, 0700); e != nil {
			t.Fatal(e)
		}
		_, err := s.Update(map[string]any{"count": 1})
		require(t, err != nil && s.Values()["count"] == float64(0))
		if e := os.Remove(s.File); e != nil {
			t.Fatal(e)
		}
		require(t, update(t, s, map[string]any{"count": 2})["count"] == float64(2))
	})
	t.Run("unknown keys retain raw JSON and decoded numbers are float64", func(t *testing.T) {
		s := New(t.TempDir(), Options{})
		write(t, s.File, `{"extra": {"value": 1.25},"count":9007199254740993}`)
		v := load(t, s)
		require(t, string(s.RawValues()["extra"]) == `{"value": 1.25}`)
		require(t, v["count"] == float64(9007199254740992))
		update(t, s, map[string]any{"combine": true})
		require(t, strings.Contains(read(t, s.File), "9007199254740993"))
	})
}

type failingRename struct {
	disk
	attempts int
	failures int
	err      error
}

func (f *failingRename) Rename(a, b string) error {
	f.attempts++
	if f.attempts <= f.failures {
		return f.err
	}
	return f.disk.Rename(a, b)
}
func TestAtomicRetries(t *testing.T) {
	for _, code := range retryErrors() {
		t.Run(code.Error(), func(t *testing.T) {
			f := &failingRename{failures: 2, err: code}
			sleeps := 0
			file := filepath.Join(t.TempDir(), "settings.json")
			e := AtomicWrite(file, []byte("ok"), Options{Files: f, ID: func() string { return "test" }, Sleep: func(d time.Duration) { require(t, d == 50*time.Millisecond); sleeps++ }})
			require(t, e == nil && f.attempts == 3 && sleeps == 2)
			require(t, read(t, file) == "ok")
		})
	}
	f := &failingRename{failures: 20, err: retryErrors()[0]}
	file := filepath.Join(t.TempDir(), "settings.json")
	e := AtomicWrite(file, []byte("ok"), Options{Files: f, ID: func() string { return "test" }, Sleep: func(time.Duration) {}})
	require(t, e != nil)
	require(t, f.attempts == 11)
	_, e = os.Stat(file + ".test.tmp")
	require(t, errors.Is(e, os.ErrNotExist))
}
