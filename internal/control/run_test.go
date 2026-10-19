package control

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/AyoubAchour/net-switch/internal/control/engine"
	"github.com/AyoubAchour/net-switch/internal/crashnet"
	"github.com/AyoubAchour/net-switch/internal/engine/singbox"
	js "github.com/AyoubAchour/net-switch/internal/jsvalue"
	"github.com/AyoubAchour/net-switch/internal/platform"
)

type runningClock struct{ origin time.Time }

func (c runningClock) Now() time.Time { return c.origin.Add(time.Since(c.origin) * 100) }
func (runningClock) After(d time.Duration) <-chan time.Time {
	return time.After(max(time.Millisecond, d/100))
}

type runningPlatform struct {
	clock    runningClock
	sequence atomic.Int64
	streams  atomic.Int64
	probes   atomic.Int64
}

func (p *runningPlatform) Call(ctx context.Context, operation string, args map[string]any) (any, error) {
	switch operation {
	case "network":
		return map[string]any{"readAt": p.clock.Now().UnixMilli(), "policy": float64(1), "adapters": []any{
			map[string]any{"alias": "Ethernet", "status": "Up", "gateway": "192.0.2.254", "ipv4s": []any{"192.0.2.1"}},
			map[string]any{"alias": "Wi-Fi", "status": "Up", "gateway": "192.0.2.254", "mediaType": "wireless", "ipv4s": []any{"192.0.2.2"}},
		}, "defaultRoutes": []any{map[string]any{"interfaceAddress": "192.0.2.1"}, map[string]any{"interfaceAddress": "192.0.2.2"}}}, nil
	case "line-check":
		p.probes.Add(1)
		return engine.ProbeResult{Outcome: engine.OK, Delay: ptr(18.0)}, nil
	case "elevated":
		return true, nil
	case "app-info", "installed-apps":
		return []any{}, nil
	case "close-tcp":
		return map[string]any{"closed": 0, "failed": 0, "gone": 0, "codes": []any{}}, nil
	}
	return nil, nil
}
func (p *runningPlatform) Stream(ctx context.Context, mode string, emit func([]byte), report func(error)) {
	ticker := time.NewTicker(4 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		var value any
		switch mode {
		case "network":
			value, _ = p.Call(ctx, "network", nil)
		case "meters":
			value = map[string]any{"adapters": []any{map[string]any{"alias": "Ethernet", "rx": p.sequence.Add(100), "tx": 0}}}
		case "outside":
			value = map[string]any{"outside": []any{}}
		}
		b, err := js.Marshal(value)
		if err != nil {
			report(err)
			continue
		}
		p.streams.Add(1)
		emit(b)
	}
}

func TestRunLoopsAndRealAdapterConcurrent(t *testing.T) {
	c, _, _, files := testCore(t, map[string]any{"lines": testLines()})
	clock := runningClock{time.Now()}
	system := &runningPlatform{clock: clock}
	c.op.Clock, c.op.Platform = clock, system
	var calls, starts atomic.Int64
	var a *singbox.Adapter
	c.op.Crash = crashnet.New(c.op.Log, func(ctx context.Context) error { defer c.cancel(); return a.Stop(ctx) })
	a = singbox.New(singbox.Options{
		Executable: "/test/engine/sing-box.exe", DataDir: "/test", Mode: "tun", Platform: system, Files: c.op.IO, Now: clock.Now, Crash: c.op.Crash,
		Verify: func() error { return nil }, FreePort: func() (int, error) { return 49000, nil }, ListFiles: func(string) ([]string, error) { return nil, nil },
		Sleep: func(ctx context.Context, _ time.Duration) error { return ctx.Err() },
		StartProcess: func(string, string, string) (singbox.Child, error) {
			starts.Add(1)
			return &replayChild{closed: make(chan struct{})}, nil
		},
		HTTP: &http.Client{Transport: replayTransport(func(r *http.Request) (*http.Response, error) {
			calls.Add(1)
			body := `{}`
			if r.URL.Path == "/connections" {
				body = `{"connections":[{"id":"flow","metadata":{"processPath":"C:\\Apps\\Firefox.exe"},"chains":["line-b2"],"download":10,"upload":1,"start":"2026-01-01T00:00:00Z"}]}`
			}
			return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(body)), Header: http.Header{}, Request: r}, nil
		})},
	})
	c.op.Engine = a
	var tasks sync.WaitGroup
	var taskMu sync.Mutex
	closed := false
	c.op.Background = func(f func()) {
		taskMu.Lock()
		defer taskMu.Unlock()
		if closed {
			return
		}
		tasks.Add(1)
		go func() { defer tasks.Done(); defer c.op.Crash.Recover("concurrent Run test"); f() }()
	}
	if err := c.RefreshAdapters(context.Background()); err != nil {
		t.Fatal(err)
	}
	c.Run()
	deadline := time.Now().Add(5 * time.Second)
	for a.Snapshot().Status != "on" && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if a.Snapshot().Status != "on" {
		t.Fatal("Run supervisor never started adapter")
	}
	var clients sync.WaitGroup
	for client := 0; client < 4; client++ {
		clients.Add(1)
		go func(index int) {
			defer clients.Done()
			for i := 0; i < 15; i++ {
				if index == 0 {
					_, _ = c.Action(context.Background(), "POST", "/api/app-line", map[string]any{"path": `C:\Apps\Firefox.exe`, "line": "a1"})
				} else if index == 1 {
					_, _ = c.Action(context.Background(), "POST", "/api/reconnect", map[string]any{"key": `c:\apps\firefox.exe`})
				} else {
					c.State()
				}
				time.Sleep(3 * time.Millisecond)
			}
		}(client)
	}
	clients.Wait()
	if err := c.Shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}
	taskMu.Lock()
	closed = true
	taskMu.Unlock()
	tasks.Wait()
	if starts.Load() < 1 || calls.Load() < 10 || system.streams.Load() < 6 || system.probes.Load() < 2 {
		t.Fatalf("loops did not execute: starts=%d calls=%d streams=%d probes=%d", starts.Load(), calls.Load(), system.streams.Load(), system.probes.Load())
	}
	t.Logf("real adapter: %d starts, %d HTTP exchanges, %d streamed snapshots, %d probes", starts.Load(), calls.Load(), system.streams.Load(), system.probes.Load())
	files.mu.Lock()
	defer files.mu.Unlock()
	for _, line := range files.logs {
		if strings.Contains(line, "fatal control error") {
			t.Fatal(line)
		}
	}
}

type panicEngine struct {
	engine.Engine
	where string
}

func (e panicEngine) Snapshot() engine.Snapshot {
	if e.where == "supervisor" {
		panic("supervisor fault")
	}
	return e.Engine.Snapshot()
}
func (e panicEngine) Connections(ctx context.Context) ([]engine.Connection, error) {
	if e.where == "poll" {
		panic("poll fault")
	}
	return e.Engine.Connections(ctx)
}
func (e panicEngine) Probe(ctx context.Context, r engine.ProbeRequest) engine.ProbeResult {
	if e.where == "probe" {
		panic("probe fault")
	}
	return e.Engine.Probe(ctx, r)
}

type panicStream struct{ platform.System }

func (panicStream) Stream(context.Context, string, func([]byte), func(error)) {
	panic("stream callback fault")
}

func TestCrashNetStopsEngineAfterBackgroundPanic(t *testing.T) {
	for _, where := range []string{"poll", "supervisor", "probe", "stream"} {
		t.Run(where, func(t *testing.T) {
			c, e, _, files := testCore(t, map[string]any{"lines": testLines()})
			c.sampleLinesLocked(e.Snapshot())
			if err := c.Start(context.Background()); err != nil {
				t.Fatal(err)
			}
			c.op.Engine = panicEngine{e, where}
			for _, l := range c.lanes {
				l.probeAt = nil
			}
			if where == "stream" {
				c.op.Platform = panicStream{c.op.Platform}
			}
			var jobs sync.WaitGroup
			c.op.Background = func(f func()) {
				jobs.Add(1)
				go func() { defer jobs.Done(); defer c.op.Crash.Recover("Run background task"); f() }()
			}
			c.Run()
			select {
			case err := <-c.op.Crash.Failures():
				if !strings.Contains(err.Error(), where) {
					t.Fatal(err)
				}
			case <-time.After(time.Second):
				t.Fatal("panic cleanup did not finish")
			}
			if e.Snapshot().Status != "off" {
				t.Fatal("engine survived panic")
			}
			jobs.Wait()
			files.mu.Lock()
			log := strings.Join(files.logs, "\n")
			files.mu.Unlock()
			if !strings.Contains(log, fmt.Sprintf("%s fault", where)) && !strings.Contains(log, "stream callback fault") {
				t.Fatal("panic was not logged")
			}
		})
	}
}
