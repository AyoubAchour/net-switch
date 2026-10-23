package lifecycle

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/AyoubAchour/net-switch/internal/engine/host"
	"github.com/AyoubAchour/net-switch/internal/settings"
	"golang.org/x/sys/windows"
)

type nativeReadPublishFiles struct{ renameFiles }

func (nativeReadPublishFiles) Rename(from, to string) error { return replaceNativeState(from, to) }

func TestNativeReadersShareAtomicPublication(t *testing.T) {
	dir := t.TempDir()
	instance := "0123456789abcdef0123456789abcdef"
	outcomePath, _ := host.OutcomePath(dir, instance)
	statePath := filepath.Join(dir, "engine-state.json")
	out := host.Outcome{Instance: instance, State: "complete", Child: &host.ChildOutcome{PID: 123, Code: 1, Forced: true}}
	record := host.Record{Schema: 1, Instance: instance, Epoch: 42}
	// Exercise saveNative's actual replacement and sync without requiring a
	// SYSTEM-owned service directory in a pure unit test.
	publish := func(path string, value any) error {
		return saveNativeWith(path, value, settings.Options{Files: nativeReadPublishFiles{}, SyncFile: syncFile, SyncParent: SyncDirectory})
	}
	for path, value := range map[string]any{outcomePath: out, statePath: record} {
		if err := publish(path, value); err != nil {
			t.Fatal(err)
		}
	}
	readers := []struct {
		name, path string
		read       func() error
	}{
		{"outcome", outcomePath, func() error {
			v, err := host.ReadOutcome(dir, instance)
			if err == nil && (v.Child == nil || !v.Child.Forced || v.Child.Completed) {
				return fmt.Errorf("classification changed: %+v", v.Child)
			}
			return err
		}},
		{"record", statePath, func() error { _, err := host.ReadRecord(statePath); return err }},
		{"open", statePath, func() error {
			_, err := host.Open(statePath, instance, func(host.Record) error { return nil })
			return err
		}},
	}
	for _, reader := range readers {
		t.Run(reader.name, func(t *testing.T) {
			name, err := windows.UTF16PtrFromString(reader.path)
			if err != nil {
				t.Fatal(err)
			}
			h, err := windows.CreateFile(name, windows.DELETE, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil, windows.OPEN_EXISTING, 0, 0)
			if err != nil {
				t.Fatal(err)
			}
			defer windows.CloseHandle(h)
			// Reproduce the old reader's conflict while a publisher holds DELETE.
			old, err := os.Open(reader.path)
			if old != nil {
				old.Close()
			}
			if !errors.Is(err, windows.ERROR_SHARING_VIOLATION) {
				t.Fatal("missing old-reader failure precondition", err)
			}
			if err := reader.read(); err != nil {
				t.Fatal("reader rejected concurrent publisher", err)
			}
		})
	}
	stop := make(chan struct{})
	var workers sync.WaitGroup
	var reads atomic.Int64
	failures := make(chan error, 1)
	for _, reader := range readers {
		workers.Go(func() {
			for {
				select {
				case <-stop:
					return
				default:
				}
				if err := reader.read(); err != nil {
					select {
					case failures <- fmt.Errorf("%s: %w", reader.name, err):
					default:
					}
					return
				}
				reads.Add(1)
				time.Sleep(time.Millisecond)
			}
		})
	}
	stopReaders := sync.OnceFunc(func() { close(stop); workers.Wait() })
	defer stopReaders()
	for i := 0; i < 64; i++ {
		record.Epoch++
		if err := publish(statePath, record); err != nil {
			t.Fatal("state publish", err)
		}
		if err := publish(outcomePath, out); err != nil {
			t.Fatal("outcome publish", err)
		}
	}
	stopReaders()
	if reads.Load() == 0 {
		t.Fatal("no concurrent reads")
	}
	select {
	case err := <-failures:
		t.Fatal(err)
	default:
	}
	t.Logf("native publication race: publishes=128 reads=%d", reads.Load())
}

func TestNativeReadersPreserveNotExist(t *testing.T) {
	dir := t.TempDir()
	_, err := host.ReadOutcome(dir, "0123456789abcdef0123456789abcdef")
	if !os.IsNotExist(err) {
		t.Fatal("outcome missing-file identity lost", err)
	}
	_, err = host.ReadRecord(filepath.Join(dir, "missing"))
	if !os.IsNotExist(err) {
		t.Fatal("state missing-file identity lost", err)
	}
}
