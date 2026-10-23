package lifecycle

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/AyoubAchour/net-switch/internal/settings"
)

// renameFiles mirrors Control's journal writes: os.WriteFile for the temporary
// file and os.Rename to publish it over the previous journal.
type renameFiles struct{}

func (renameFiles) ReadFile(p string) ([]byte, error) { return os.ReadFile(p) }
func (renameFiles) WriteFile(p string, b []byte, m os.FileMode) error {
	return os.WriteFile(p, b, m)
}
func (renameFiles) Rename(from, to string) error { return os.Rename(from, to) }
func (renameFiles) Remove(p string) error        { return os.Remove(p) }

func TestReadToleratesRenamePublish(t *testing.T) {
	path := filepath.Join(t.TempDir(), "control-journal.json")
	if err := os.WriteFile(path, []byte(`{"revision":0,"failures":[]}`), 0600); err != nil {
		t.Fatal(err)
	}
	const publishes = 400
	var reads, failures atomic.Int64
	var mu sync.Mutex
	var firstErr error
	stop := make(chan struct{})
	var readers sync.WaitGroup
	for i := 0; i < 1; i++ {
		readers.Add(1)
		go func() {
			defer readers.Done()
			for {
				var value struct {
					Revision int64 `json:"revision"`
				}
				err := Read(path, &value)
				reads.Add(1)
				if err != nil {
					failures.Add(1)
					mu.Lock()
					if firstErr == nil {
						firstErr = err
					}
					mu.Unlock()
				}
				select {
				case <-stop:
					return
				default:
					time.Sleep(10 * time.Millisecond)
				}
			}
		}()
	}
	for i := 0; i < publishes; i++ {
		body := fmt.Sprintf(`{"revision":%d,"failures":[]}`, i)
		if err := settings.AtomicWrite(path, []byte(body), settings.Options{Files: renameFiles{}}); err != nil {
			close(stop)
			readers.Wait()
			t.Fatalf("publish %d failed: %v", i, err)
		}
	}
	close(stop)
	readers.Wait()
	if reads.Load() == 0 {
		t.Fatal("no reads ran")
	}
	if n := failures.Load(); n != 0 {
		mu.Lock()
		defer mu.Unlock()
		t.Fatalf("%d of %d reads failed while the journal was published; first: %v", n, reads.Load(), firstErr)
	}
}
