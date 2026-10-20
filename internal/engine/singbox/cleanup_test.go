package singbox

import (
	"context"
	"io"
	"io/fs"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/AyoubAchour/net-switch/internal/settings"
)

type cleanupFiles struct {
	*testFiles
	mu      sync.Mutex
	entered chan struct{}
	release chan struct{}
	err     error
	deletes int
}

func (f *cleanupFiles) Remove(path string) error {
	if filepath.Base(path) != "engine.pid" {
		return f.testFiles.Remove(path)
	}
	f.mu.Lock()
	f.deletes++
	first := f.deletes == 1
	f.mu.Unlock()
	if first && f.entered != nil {
		close(f.entered)
		<-f.release
	}
	if f.err != nil {
		return f.err
	}
	return f.testFiles.Remove(path)
}

func TestExitOwnsPIDCleanupThroughConcurrentStop(t *testing.T) {
	for _, deletion := range []struct {
		name string
		err  error
	}{{"removed", nil}, {"already gone", fs.ErrNotExist}, {"access denied", fs.ErrPermission}} {
		t.Run(deletion.name, func(t *testing.T) {
			files := &cleanupFiles{testFiles: &testFiles{data: map[string][]byte{}}, entered: make(chan struct{}), release: make(chan struct{}), err: deletion.err}
			var release sync.Once
			t.Cleanup(func() { release.Do(func() { close(files.release) }) })
			reader, writer := io.Pipe()
			child := &controlledChild{done: make(chan struct{}), output: reader, writer: writer}
			var logs []string
			a := New(Options{DataDir: "/test", Files: settings.Options{Files: files}, Log: func(s string) { logs = append(logs, s) },
				Verify: func() error { return nil }, FreePort: func() (int, error) { return 49000, nil },
				ListFiles: func(string) ([]string, error) { return nil, nil }, StartProcess: func(string, string, string) (Child, error) { return child, nil },
				HTTP: &http.Client{Transport: roundTrip(func(r *http.Request) (*http.Response, error) {
					return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(`{}`)), Header: http.Header{}}, nil
				})},
			})
			base, _, _, _ := fixtureAdapter(t)
			if err := a.Start(context.Background(), base.Snapshot().Policy); err != nil || a.Snapshot().Status != "on" {
				t.Fatal(err, a.Snapshot())
			}
			if _, err := files.ReadFile(filepath.Join("/test", "engine.pid")); err != nil {
				t.Fatal("PID record was never created", err)
			}
			child.finish(nil)
			<-files.entered // The exit owner has cleared child but is still deleting.
			stopped := make(chan error, 1)
			go func() { stopped <- a.Stop(context.Background()) }()
			select {
			case err := <-stopped:
				t.Fatalf("Stop returned before exit cleanup completed: %v", err)
			case <-time.After(25 * time.Millisecond):
			}
			release.Do(func() { close(files.release) })
			if err := <-stopped; err != nil || a.Snapshot().Status != "off" {
				t.Fatal("cleanup failure failed Stop", err, a.Snapshot())
			}
			if files.deletes != 1 {
				t.Fatalf("PID cleanup has %d owners", files.deletes)
			}
			if deletion.err == nil {
				if _, err := files.ReadFile(filepath.Join("/test", "engine.pid")); err != fs.ErrNotExist {
					t.Fatal("exit owner did not remove the pre-existing PID record", err)
				}
				// A later Stop may encounter an unrelated stale record, as the
				// real routing fixture does. Completed ownership must not hide it.
				files.data[filepath.Join("/test", "engine.pid")] = []byte("invalid")
				if err := a.Stop(context.Background()); err != nil {
					t.Fatal(err)
				}
				if _, err := files.ReadFile(filepath.Join("/test", "engine.pid")); err != fs.ErrNotExist {
					t.Fatal("later Stop ignored a new orphan PID record", err)
				}
			}
			warning := strings.Join(logs, "\n")
			if deletion.err == fs.ErrPermission && (!strings.Contains(warning, "cleanup warning") || !strings.Contains(warning, "engine.pid")) {
				t.Fatal("failed cleanup was not diagnosed", warning)
			}
			if deletion.err == fs.ErrNotExist && warning != "" {
				t.Fatal("missing PID is not a warning", warning)
			}
		})
	}
}

func TestOrphanPIDCleanupFailureDoesNotFailStop(t *testing.T) {
	for _, failure := range []error{fs.ErrNotExist, fs.ErrPermission} {
		files := &cleanupFiles{testFiles: &testFiles{data: map[string][]byte{filepath.Join("/test", "engine.pid"): []byte("invalid")}}, err: failure}
		a := New(Options{DataDir: "/test", Files: settings.Options{Files: files}})
		if err := a.Stop(context.Background()); err != nil || a.Snapshot().Status != "off" {
			t.Fatal(err, a.Snapshot())
		}
	}
}
