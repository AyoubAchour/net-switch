package singbox

import (
	"context"
	"errors"
	"io"
	"io/fs"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/AyoubAchour/net-switch/internal/apps"
	"github.com/AyoubAchour/net-switch/internal/control/engine"
	"github.com/AyoubAchour/net-switch/internal/settings"
)

func TestSelectorFailureKeepsRulesAndRetriesOnlyUnconfirmedSwitch(t *testing.T) {
	a, files, _, _ := fixtureAdapter(t)
	a.laneKnown = map[string]bool{"aa": true, "bb": true}
	p := a.Snapshot().Policy
	p.AppLines = apps.Pins{{Path: `C:\Apps\Firefox.exe`, LineID: "bb"}}
	p.Lanes["aa"], p.Lanes["bb"] = "bb", "aa"
	var requests []string
	failed := false
	a.o.HTTP = &http.Client{Transport: roundTrip(func(r *http.Request) (*http.Response, error) {
		requests = append(requests, r.URL.Path)
		status := 200
		if r.URL.Path == "/proxies/lane-bb" && !failed {
			failed = true
			status = 503
		}
		return &http.Response{StatusCode: status, Body: io.NopCloser(strings.NewReader(`{}`)), Header: http.Header{}, Request: r}, nil
	})}
	if _, err := a.Apply(context.Background(), revision(2, p)); err == nil || !strings.Contains(err.Error(), "PUT /proxies/lane-bb") {
		t.Fatal(err)
	}
	writes := files.writes
	if writes != 4 {
		t.Fatalf("failed selector rewrote rules: %d writes", writes)
	}
	if a.Snapshot().Policy.Lanes["aa"] != "bb" {
		t.Fatal("successful switch was reverted")
	}
	if _, err := a.Apply(context.Background(), revision(3, p)); err != nil {
		t.Fatal(err)
	}
	if files.writes != writes || strings.Join(requests, ",") != "/proxies/lane-aa,/proxies/lane-bb,/proxies/lane-bb" {
		t.Fatal(files.writes, requests)
	}
}

type brokenChecker struct{}

func (brokenChecker) Call(context.Context, string, map[string]any) (any, error) {
	return nil, errors.New("worker crashed")
}
func (brokenChecker) Stream(context.Context, string, func([]byte), func(error)) {}
func TestCheckWorkerFailureIsLoggedAndRateLimited(t *testing.T) {
	a, _, now, _ := fixtureAdapter(t)
	a.o.Platform = brokenChecker{}
	var logs []string
	a.o.Log = func(s string) { logs = append(logs, s) }
	for i := 0; i < 10; i++ {
		if got := a.Probe(context.Background(), engine.ProbeRequest{Line: "aa"}); got.Outcome != engine.Unavailable {
			t.Fatal(got)
		}
	}
	if len(logs) != 1 || !strings.Contains(logs[0], "worker crashed") {
		t.Fatal(logs)
	}
	*now = now.Add(30 * time.Second)
	a.Probe(context.Background(), engine.ProbeRequest{Line: "aa"})
	if len(logs) != 2 {
		t.Fatal(logs)
	}
}

type synchronizedFiles struct {
	mu         sync.Mutex
	data       map[string][]byte
	denyRemove string
}

func (f *synchronizedFiles) ReadFile(p string) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	b, ok := f.data[p]
	if !ok {
		return nil, fs.ErrNotExist
	}
	return append([]byte{}, b...), nil
}
func (f *synchronizedFiles) WriteFile(p string, b []byte, _ fs.FileMode) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.data[p] = append([]byte{}, b...)
	return nil
}
func (f *synchronizedFiles) Rename(a, b string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.data[b] = f.data[a]
	delete(f.data, a)
	return nil
}
func (f *synchronizedFiles) Remove(p string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if filepath.Base(p) == f.denyRemove {
		return errors.New("read-only stale file")
	}
	delete(f.data, p)
	return nil
}

type controlledChild struct {
	done   chan struct{}
	once   sync.Once
	output *io.PipeReader
	writer *io.PipeWriter
	err    error
}

func (p *controlledChild) PID() int          { return 456 }
func (p *controlledChild) Stdout() io.Reader { return p.output }
func (p *controlledChild) Stderr() io.Reader { return strings.NewReader("") }
func (p *controlledChild) Wait() error       { <-p.done; return p.err }
func (p *controlledChild) Kill() error       { p.finish(nil); return nil }
func (p *controlledChild) finish(err error) {
	p.once.Do(func() { p.err = err; p.writer.Close(); close(p.done) })
}

type exitFailure int

func (e exitFailure) Error() string { return "engine exit" }
func (e exitFailure) ExitCode() int { return int(e) }

func TestStartIgnoresStaleCleanupErrorsAndCrashIncludesSixLines(t *testing.T) {
	for _, listingFails := range []bool{true, false} {
		t.Run(map[bool]string{true: "list failure", false: "delete failure"}[listingFails], func(t *testing.T) {
			files := &synchronizedFiles{data: map[string][]byte{}, denyRemove: "apps-dead.json"}
			reader, writer := io.Pipe()
			child := &controlledChild{done: make(chan struct{}), output: reader, writer: writer}
			a := New(Options{DataDir: "/test", Mode: "tun", Files: settings.Options{Files: files}, Verify: func() error { return nil }, FreePort: func() (int, error) { return 49000, nil },
				ListFiles: func(string) ([]string, error) {
					if listingFails {
						return nil, errors.New("cannot list")
					}
					return []string{"apps-dead.json"}, nil
				},
				StartProcess: func(string, string, string) (Child, error) { return child, nil },
				HTTP: &http.Client{Transport: roundTrip(func(r *http.Request) (*http.Response, error) {
					return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(`{}`)), Header: http.Header{}, Request: r}, nil
				})},
			})
			base, _, _, _ := fixtureAdapter(t)
			if err := a.Start(context.Background(), base.Snapshot().Policy); err != nil || a.Snapshot().Status != "on" {
				t.Fatal(err, a.Snapshot())
			}
			if _, err := io.WriteString(writer, "one\ntwo\nthree\nfour\nfive\nsix\nseven\neight\n"); err != nil {
				t.Fatal(err)
			}
			child.finish(exitFailure(7))
			a.mu.Lock()
			done := a.exited
			a.mu.Unlock()
			<-done
			want := "Routing stopped unexpectedly (exit code 7).\nthree\nfour\nfive\nsix\nseven\neight"
			if s := a.Snapshot(); s.Error == nil || *s.Error != want {
				t.Fatalf("crash message: %+v", s)
			}
		})
	}
}
