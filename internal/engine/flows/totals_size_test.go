package flows

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/AyoubAchour/net-switch/internal/engine/platform"
	"github.com/AyoubAchour/net-switch/internal/engine/policy"
)

// This uses admission/accounting, not a fabricated oversized reply. At the
// legitimate flow limit every flow may belong to a different 512-byte app ID.
// Closing each ticket also proves that the problem persists without live flows.
func TestTotalsMaximumCardinalityMeasurement(t *testing.T) {
	f := New(Defaults(), nil)
	config := policy.Config{Combine: true, Shares: map[string]uint64{}}
	for i := range 255 {
		id := fmt.Sprintf("%03d%s", i, strings.Repeat("l", 61))
		config.Lines = append(config.Lines, platform.Line{ID: id})
		config.Shares[id] = 1
	}
	if _, err := f.Apply(policy.Revision{N: 1, Hash: policy.Hash(config), Config: config}); err != nil {
		t.Fatal(err)
	}
	for i := range Defaults().Flows {
		app := fmt.Sprintf("%08d%s", i, strings.Repeat("x", 504))
		ticket := admit(t, f, "tcp", app)
		ticket.Add(1, 2)
		ticket.Close()
	}
	totals := f.Totals()
	b, err := json.Marshal(totals)
	if err != nil {
		t.Fatal(err)
	}
	if len(totals.Apps) != Defaults().Flows || len(totals.Lines) != 255 || f.Stats().Flows != 0 {
		t.Fatal("measurement did not account for every admitted, closed app")
	}
	t.Logf("TOTALS_UNPAGED apps=%d lines=%d closed_flows=%d bytes=%d reply_limit=%d", len(totals.Apps), len(totals.Lines), Defaults().Flows, len(b), 1<<20)
	if len(b) <= 1<<20 {
		t.Fatal("maximum-cardinality reproduction no longer exceeds the wire bound")
	}
	checkTotalsPages(t, f, totals)
}

func checkTotalsPages(t *testing.T, f *Table, want Totals) {
	t.Helper()
	got := Totals{Apps: map[string]Bytes{}, Lines: map[string]Bytes{}}
	cursor, pages, largest := "", 0, 0
	for {
		page, err := f.PageTotals(cursor)
		if err != nil {
			t.Fatal(err)
		}
		b, err := json.Marshal(map[string]any{"id": strings.Repeat("i", 128), "result": page})
		if err != nil || len(b)+1 > 1<<20 {
			t.Fatalf("totals page %d bytes: %v", len(b), err)
		}
		largest = max(largest, len(b)+1)
		for id, n := range page.Apps {
			if _, exists := got.Apps[id]; exists {
				t.Fatal("duplicate app", id)
			}
			got.Apps[id] = n
		}
		for id, n := range page.Lines {
			if _, exists := got.Lines[id]; exists {
				t.Fatal("duplicate line", id)
			}
			got.Lines[id] = n
		}
		pages++
		if page.Cursor == "" {
			break
		}
		cursor = page.Cursor
	}
	a, _ := json.Marshal(got)
	b, _ := json.Marshal(want)
	if string(a) != string(b) {
		t.Fatal("paged accounting differs from the independently summed snapshot")
	}
	if f.Stats().SnapshotBytes != 0 {
		t.Fatal("completed totals snapshot retained its reservation")
	}
	t.Logf("TOTALS_PAGED pages=%d largest_reply=%d apps=%d lines=%d", pages, largest, len(got.Apps), len(got.Lines))
}

func TestTotalsSnapshotStableAcrossCloseAndNewTraffic(t *testing.T) {
	f := table(t, Defaults())
	for i := range 80 {
		x := admit(t, f, "tcp", fmt.Sprintf("app-%03d", i))
		x.Add(3, 7)
		x.Close()
	}
	live := admit(t, f, "tcp", "zz-live")
	live.Add(5, 11)
	first, err := f.PageTotals("")
	if err != nil || first.Cursor == "" {
		t.Fatal(first, err)
	}
	live.Add(100, 200)
	live.Close()
	late := admit(t, f, "udp", "zz-new")
	late.Add(9, 13)
	late.Close()
	last, err := f.PageTotals(first.Cursor)
	if err != nil || last.Cursor != "" {
		t.Fatal(last, err)
	}
	if last.Apps["zz-live"] != (Bytes{5, 11}) {
		t.Fatal("frozen live counters changed", last.Apps)
	}
	if _, exists := last.Apps["zz-new"]; exists {
		t.Fatal("late flow entered old snapshot")
	}
	checkTotalsPages(t, f, f.Totals())
}

func TestTotalsSharesSnapshotBudgetAndExpiresWithoutLosingAccounting(t *testing.T) {
	f := table(t, Defaults())
	for i := range 80 {
		admit(t, f, "tcp", fmt.Sprint(i)).Close()
	}
	now := time.Now()
	f.now = func() time.Time { return now }
	first, err := f.PageTotals("")
	if err != nil {
		t.Fatal(err)
	}
	for range Defaults().Snapshots - 1 {
		if _, err := f.PageTotals(""); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := f.Page(""); err != ErrBudget {
		t.Fatal("flows bypassed totals count budget", err)
	}
	if _, err := f.PageTotals(""); err != ErrBudget {
		t.Fatal("totals bypassed count budget", err)
	}
	now = now.Add(10 * time.Second)
	if _, err := f.PageTotals(first.Cursor); err == nil {
		t.Fatal("expired totals snapshot accepted")
	}
	if f.Stats().SnapshotBytes != 0 {
		t.Fatal("expired reservations leaked")
	}
	checkTotalsPages(t, f, f.Totals())
	f.limits.SnapshotBytes = 1
	if _, err := f.PageTotals(""); err != ErrBudget || f.Stats().SnapshotBytes != 0 {
		t.Fatal("byte reservation failed", err)
	}
	if len(f.Totals().Apps) != 80 {
		t.Fatal("budget refusal truncated accounting")
	}
	for _, cursor := range []string{"1:2", "totals:1:-1", "totals:bad:0", "totals:1:99999999999999999999999"} {
		if _, err := f.PageTotals(cursor); err == nil {
			t.Fatal("invalid cursor accepted", cursor)
		}
	}
}
