package protocol

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/AyoubAchour/net-switch/internal/engine/platform"
)

type observedRuntime struct {
	*runtimeFake
	state   string
	started time.Time
}

func (r *observedRuntime) LiveState() (string, time.Time) { return r.state, r.started }

func TestStatusDoesNotExposeHistoryOrUnfinishedCaptureAsLoaded(t *testing.T) {
	s, base, req := setup(t)
	r := &observedRuntime{runtimeFake: base, state: "off"}
	s.runtime = r
	for _, state := range []string{"off", "starting", "on", "stopping", "error"} {
		r.state, r.started = state, time.Unix(123, 0)
		if _, err := base.table.Apply(revision(1)); err != nil {
			t.Fatal(err)
		}
		out := call(t, s, req("status")).Result.(Status)
		if out.State != state || (out.Applied != nil) != (state == "on") {
			t.Fatal("invalid loaded state", out)
		}
		hello := call(t, s, Request{ID: "hello", Method: "hello"}).Result.(map[string]any)
		wire, err := json.Marshal(hello)
		if err != nil || len(wire) > 4096 {
			t.Fatalf("hello grew beyond bounded metadata: %d %v", len(wire), err)
		}
		status := hello["status"].(Status)
		if (status.Applied != nil) != (state == "on") {
			t.Fatal("hello published unconfirmed forwarding", status)
		}
	}
}

func TestTotalsProtocolFencesAndDeliversAllPages(t *testing.T) {
	s, base, req := setup(t)
	rev := revision(1)
	start := req("start")
	start.Revision = &rev
	call(t, s, start)
	for i := range 300 {
		f, err := base.table.Begin("tcp", platform.Tuple{Source: netip.MustParseAddrPort("198.18.0.2:4000"), Destination: netip.MustParseAddrPort("203.0.113.1:443")})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.Resolve(platform.Owner{AppID: fmt.Sprint(i) + strings.Repeat("\x00", 500)}); err != nil {
			t.Fatal(err)
		}
		f.Add(17, 29)
		f.Close()
	}
	request := req("totals")
	apps, lines, pages := 0, 0, 0
	for {
		reply := call(t, s, request)
		b, err := json.Marshal(reply)
		if err != nil || len(b)+1 > MessageLimit {
			t.Fatal("escaped identities exceed reply bound", len(b), err)
		}
		var page struct {
			Apps    map[string]any `json:"apps"`
			Lines   map[string]any `json:"lines"`
			Cursor  string         `json:"cursor"`
			Receipt string         `json:"receipt"`
		}
		body, _ := json.Marshal(reply.Result)
		if err := json.Unmarshal(body, &page); err != nil {
			t.Fatal(err)
		}
		apps += len(page.Apps)
		lines += len(page.Lines)
		pages++
		if page.Cursor == "" {
			ack := req("ackTotals")
			ack.Receipt, ack.OpID = page.Receipt, "read-accounting"
			call(t, s, ack)
			call(t, s, ack) // the same receipt operation is safe after its reply was lost
			break
		}
		request.Cursor = page.Cursor
		fenced := request
		fenced.Epoch++
		if s.Handle(context.Background(), fenced).Error == "" {
			t.Fatal("old snapshot cursor bypassed fencing")
		}
	}
	if apps != 300 || lines != 1 || pages < 2 {
		t.Fatal("totals were truncated", apps, lines, pages)
	}
}
