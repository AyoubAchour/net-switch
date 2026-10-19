package control

import (
	"bytes"
	"context"
	"fmt"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	js "github.com/AyoubAchour/net-switch/internal/jsvalue"
)

func TestNetworkClockStepDoesNotFreezeSnapshots(t *testing.T) {
	c, _, clock, _ := testCore(t, map[string]any{"lines": testLines()})
	p := c.op.Platform.(*fakePlatform)
	metric := float64(10)
	p.override = func(name string, args map[string]any) (any, error, bool) {
		if name != "network" {
			return nil, nil, false
		}
		return map[string]any{"readAt": float64(clock.Now().UnixMilli()), "adapters": []any{map[string]any{"alias": "Ethernet", "metric": metric}}}, nil, true
	}
	if err := c.RefreshAdapters(context.Background()); err != nil {
		t.Fatal(err)
	}
	clock.advance(-3600000)
	metric = 42
	if err := c.RefreshAdapters(context.Background()); err != nil {
		t.Fatal(err)
	}
	if c.adapters[0]["metric"] != metric {
		t.Fatal("clock rollback froze the network snapshot")
	}
}

func TestHTTPRequestPanicIsFatalAndStopsRouting(t *testing.T) {
	c, e, _, files := testCore(t, map[string]any{"lines": testLines()})
	if err := c.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	c.op.Engine = panicEngine{e, "supervisor"}
	h := &HTTP{Core: c, Port: 47821, Token: "test"}
	r := httptest.NewRequest("GET", "http://127.0.0.1:47821/api/state", nil)
	r.Header.Set("X-Token", "test")
	h.ServeHTTP(httptest.NewRecorder(), r)
	select {
	case err := <-c.op.Crash.Failures():
		if !strings.Contains(err.Error(), "HTTP request panicked") {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("request panic did not reach fatal shutdown")
	}
	if e.Snapshot().Status != "off" {
		t.Fatal("routing survived HTTP panic")
	}
	files.mu.Lock()
	defer files.mu.Unlock()
	if !strings.Contains(strings.Join(files.logs, "\n"), "fatal control error: HTTP request panicked") {
		t.Fatal("fatal request was not diagnosed")
	}
}

func TestInitialLaneAcknowledgementIndependentOfPollOrder(t *testing.T) {
	var states []any
	var logs [][]string
	for _, pollFirst := range []bool{false, true} {
		c, _, _, files := testCore(t, map[string]any{"lines": testLines()})
		if pollFirst {
			if err := c.Poll(context.Background()); err != nil {
				t.Fatal(err)
			}
		}
		if err := c.Supervise(context.Background()); err != nil {
			t.Fatal(err)
		}
		lanes := []any{}
		for _, raw := range array(c.State()["lines"]) {
			line := js.Object(raw)
			lanes = append(lanes, []any{line["id"], line["target"], line["connected"]})
		}
		states = append(states, lanes)
		logs = append(logs, append([]string{}, files.logs...))
	}
	if !reflect.DeepEqual(states[0], states[1]) || !reflect.DeepEqual(logs[0], logs[1]) {
		t.Fatalf("startup depends on poll scheduling: states=%v logs=%v", states, logs)
	}
}

func TestDroppedActionRequestsUseServiceContext(t *testing.T) {
	for _, step := range []struct{ route, body string }{
		{"app-line", `{"path":"C:\\Apps\\Firefox.exe","line":"a1"}`},
		{"combine", `{"on":true}`}, {"lines/order", `{"ids":["b2","a1"]}`},
		{"lines/update", `{"id":"a1","label":"Home"}`},
		{"setup/keep-both", `{}`}, {"setup/undo", `{}`},
	} {
		t.Run(step.route, func(t *testing.T) {
			c, _, _, _ := testCore(t, map[string]any{"lines": testLines()})
			p := c.op.Platform.(*fakePlatform)
			p.override = func(name string, args map[string]any) (any, error, bool) {
				if name == "network" {
					return map[string]any{"adapters": []any{map[string]any{"alias": "Ethernet"}}}, nil, true
				}
				return nil, nil, false
			}
			h := &HTTP{Core: c, Port: 47821, Token: "test"}
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			r := httptest.NewRequest("POST", "http://127.0.0.1:47821/api/"+step.route, bytes.NewBufferString(step.body)).WithContext(ctx)
			r.Header.Set("X-Token", "test")
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code != 200 {
				t.Fatal(fmt.Sprint(w.Code), w.Body.String())
			}
		})
	}
}
