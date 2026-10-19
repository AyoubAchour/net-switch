package singbox

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"io/fs"
	"net/http"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/AyoubAchour/net-switch/internal/apps"
	"github.com/AyoubAchour/net-switch/internal/control/engine"
	js "github.com/AyoubAchour/net-switch/internal/jsvalue"
	"github.com/AyoubAchour/net-switch/internal/lines"
	"github.com/AyoubAchour/net-switch/internal/settings"
)

type testFiles struct {
	data   map[string][]byte
	fail   string
	writes int
}

func (f *testFiles) ReadFile(p string) ([]byte, error) {
	v, ok := f.data[p]
	if !ok {
		return nil, fs.ErrNotExist
	}
	return append([]byte{}, v...), nil
}
func (f *testFiles) WriteFile(p string, b []byte, _ fs.FileMode) error {
	f.data[p] = append([]byte{}, b...)
	return nil
}
func (f *testFiles) Rename(from, to string) error {
	if filepath.Base(to) == f.fail {
		f.fail = ""
		return errors.New("injected replacement failure")
	}
	f.data[to] = f.data[from]
	delete(f.data, from)
	f.writes++
	return nil
}
func (f *testFiles) Remove(p string) error { delete(f.data, p); return nil }

type roundTrip func(*http.Request) (*http.Response, error)

func (f roundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func revision(n uint64, p engine.Policy) engine.Revision {
	b, err := js.Marshal(p)
	if err != nil {
		panic(err)
	}
	sum := sha256.Sum256(b)
	return engine.Revision{Number: n, Hash: hex.EncodeToString(sum[:]), Policy: p}
}
func fixtureAdapter(t *testing.T) (*Adapter, *testFiles, *time.Time, *[]string) {
	t.Helper()
	now := time.Date(2026, 10, 19, 12, 0, 0, 0, time.UTC)
	files := &testFiles{data: map[string][]byte{}}
	requests := []string{}
	a := New(Options{DataDir: "/test", Mode: "tun", Now: func() time.Time { return now }, Sleep: func(context.Context, time.Duration) error { return nil }, Files: settings.Options{Files: files, ID: func() string { return "temp" }, Sleep: func(time.Duration) {}}, HTTP: &http.Client{Transport: roundTrip(func(r *http.Request) (*http.Response, error) {
		requests = append(requests, r.Method+" "+r.URL.Path)
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(`{}`)), Header: http.Header{}, Request: r}, nil
	})}})
	p := engine.Policy{Lines: []lines.Line{{ID: "aa", Alias: "Ethernet"}, {ID: "bb", Alias: "Wi-Fi"}}, AppLines: apps.Pins{}, Shares: lines.Shares{}, Blocked: []string{}, Lanes: map[string]string{"aa": "aa", "bb": "bb"}}
	r := revision(1, p)
	a.s = engine.Snapshot{Status: "on", Policy: clonePolicy(p), StartedWith: &p, Instance: "instance-1", AppliedRevision: 1, AppliedHash: r.Hash, AppliedAt: now}
	rules, err := RuleFiles(p)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range rules {
		files.data[filepath.Join("/test", f.Tag+".json")] = append([]byte{}, f.Bytes...)
	}
	return a, files, &now, &requests
}
func TestFailedRuleReplacementRollsBackBeforeAcknowledging(t *testing.T) {
	a, f, _, _ := fixtureAdapter(t)
	before := map[string][]byte{}
	for k, v := range f.data {
		before[k] = append([]byte{}, v...)
	}
	p := a.Snapshot().Policy
	p.AppLines = apps.Pins{{Path: `C:\Apps\Firefox.exe`, LineID: "bb"}}
	f.fail = "share-bb.json"
	if _, err := a.Apply(context.Background(), revision(2, p)); err == nil {
		t.Fatal("failed rule replacement acknowledged")
	}
	if a.Snapshot().AppliedRevision != 1 {
		t.Fatal("failed revision became current")
	}
	if !reflect.DeepEqual(f.data, before) {
		for k, v := range before {
			if !bytes.Equal(v, f.data[k]) {
				t.Errorf("rollback did not restore %s", k)
			}
		}
		t.Fatal("file set changed after rollback")
	}
}
func TestRevisionIdentityAndOriginalApplyPoint(t *testing.T) {
	a, _, now, requests := fixtureAdapter(t)
	p := a.Snapshot().Policy
	p.AppLines = apps.Pins{{Path: `C:\Apps\Firefox.exe`, LineID: "bb"}}
	r := revision(2, p)
	first, err := a.Apply(context.Background(), r)
	if err != nil {
		t.Fatal(err)
	}
	*now = now.Add(time.Minute)
	count := len(*requests)
	second, err := a.Apply(context.Background(), r)
	if err != nil {
		t.Fatal(err)
	}
	if second != first || len(*requests) != count {
		t.Fatal("repeated revision changed its acknowledgement or repeated effects")
	}
	r.Hash = "wrong"
	if _, err := a.Apply(context.Background(), r); err == nil {
		t.Fatal("wrong hash accepted")
	}
	if _, err := a.Apply(context.Background(), revision(1, p)); err == nil {
		t.Fatal("stale revision accepted")
	}
}
func TestCloseIntentSkipsNewFlowsAndIsIdempotent(t *testing.T) {
	a, _, now, requests := fixtureAdapter(t)
	a.o.HTTP = &http.Client{Transport: roundTrip(func(r *http.Request) (*http.Response, error) {
		*requests = append(*requests, r.Method+" "+r.URL.Path)
		body := `{}`
		if r.URL.Path == "/connections" {
			body = `{"connections":[{"id":"old","chains":["line-bb"],"start":"2026-10-19T11:59:00Z"},{"id":"new","chains":["line-bb"],"start":"2026-10-19T12:00:01Z"}]}`
		}
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(body)), Header: http.Header{}, Request: r}, nil
	})}
	r := engine.CloseRequest{OperationID: "close-1", Line: "bb", Instance: "instance-1", StartedBefore: *now, ConnectionIDs: []string{"old", "new", "gone"}}
	result, err := a.CloseFlows(context.Background(), r)
	if err != nil {
		t.Fatal(err)
	}
	if result.Closed != 1 || result.Gone != 2 || result.Failed != 0 {
		t.Fatal(result)
	}
	count := len(*requests)
	again, err := a.CloseFlows(context.Background(), r)
	if err != nil || again != result || len(*requests) != count {
		t.Fatal("closure retry repeated side effects")
	}
	r.Instance = "instance-2"
	if _, err := a.CloseFlows(context.Background(), r); err == nil {
		t.Fatal("wrong-instance closure accepted")
	}
}
