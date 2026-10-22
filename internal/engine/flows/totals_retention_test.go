package flows

import (
	"fmt"
	"runtime"
	"strings"
	"testing"

	"github.com/AyoubAchour/net-switch/internal/engine/platform"
	"github.com/AyoubAchour/net-switch/internal/engine/policy"
)

func TestAccountingNeverEvictsUnreadBytesAndRecoversAfterAcknowledgement(t *testing.T) {
	l := Defaults()
	l.AccountingApps = 2
	f := table(t, l)
	a := admit(t, f, "tcp", "a")
	a.Add(10, 20)
	a.Close()
	b := admit(t, f, "udp", "b")
	b.Add(30, 40)
	b.Close()
	for _, protocol := range []string{"tcp", "udp"} {
		c, err := f.Begin(protocol, tuple)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := c.Resolve(platform.Owner{AppID: "c"}); err != ErrAccounting {
			t.Fatal("new unread identity was not bounded", protocol, err)
		}
		c.Close()
	}
	if stats := f.Stats(); stats.RefusedTCP.Accounting != 1 || stats.RefusedUDP.Accounting != 1 {
		t.Fatal("accounting admission was not classified on both paths", stats)
	}
	if f.Totals().Apps["a"] != (Bytes{10, 20}) || f.Totals().Apps["b"] != (Bytes{30, 40}) {
		t.Fatal("unread bytes were discarded")
	}
	first, err := f.PageTotals("")
	if err != nil {
		t.Fatal(err)
	}
	// A live generation cannot be retired, even after its earlier bytes were read.
	a = admit(t, f, "tcp", "a")
	a.Add(5, 7)
	ack, err := f.AckTotals(first.Receipt)
	if err != nil || ack.Apps != 1 {
		t.Fatal(ack, err)
	}
	if f.Totals().Apps["a"] != (Bytes{15, 27}) {
		t.Fatal("late/live bytes lost")
	}
	a.Close()
	second, err := f.PageTotals("")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.AckTotals(second.Receipt); err != nil {
		t.Fatal(err)
	}
	a = admit(t, f, "tcp", "a")
	a.Add(3, 4)
	a.Close()
	third, err := f.PageTotals("")
	if err != nil {
		t.Fatal(err)
	}
	if third.Apps["a"].Generation == first.Apps["a"].Generation || third.Apps["a"].Bytes != (Bytes{3, 4}) {
		t.Fatal("new generation confused with an old cumulative counter")
	}
	if _, err = f.AckTotals(first.Receipt); err == nil {
		t.Fatal("expired receipt accepted")
	}
	if f.Totals().Apps["a"] != (Bytes{3, 4}) {
		t.Fatal("late receipt retired a replacement generation")
	}
}

func TestTotalsAcknowledgementRequiresFullReadAndOwnSnapshot(t *testing.T) {
	f := table(t, Defaults())
	for i := range 1100 {
		x := admit(t, f, "tcp", fmt.Sprintf("%04d%s", i, strings.Repeat("x", 508)))
		x.Add(1, 2)
		x.Close()
	}
	first, err := f.PageTotals("")
	if err != nil || first.Cursor == "" {
		t.Fatal(first, err)
	}
	if _, err := f.AckTotals(first.Receipt); err == nil {
		t.Fatal("partial read retired unread bytes")
	}
	if _, err := f.PageTotals(fmt.Sprintf("%s:%d", first.Receipt, first.Count)); err == nil {
		t.Fatal("skipping unread pages was accepted")
	}
	other := table(t, Defaults())
	foreign, err := other.PageTotals("")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := other.AckTotals(first.Receipt); err == nil {
		t.Fatal("foreign receipt retired another instance")
	}
	if _, err := f.PageTotals(foreign.Receipt + ":0"); err == nil {
		t.Fatal("foreign cursor entered snapshot")
	}
	last, err := f.PageTotals(first.Cursor)
	if err != nil || last.Cursor != "" {
		t.Fatal(last, err)
	}
	if _, err := f.AckTotals(last.Receipt); err != nil {
		t.Fatal(err)
	}
	if len(f.Totals().Apps) != 0 {
		t.Fatal("complete consumed idle set was retained")
	}
}

func TestOverlappingTotalsAckCannotRetireReplacementGeneration(t *testing.T) {
	f := table(t, Defaults())
	x := admit(t, f, "tcp", "reused")
	x.Add(7, 11)
	x.Close()
	a, err := f.PageTotals("")
	if err != nil {
		t.Fatal(err)
	}
	b, err := f.PageTotals("")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.AckTotals(a.Receipt); err != nil {
		t.Fatal(err)
	}
	x = admit(t, f, "udp", "reused")
	x.Add(7, 11) // identical bytes make the generation check essential
	x.Close()
	ack, err := f.AckTotals(b.Receipt)
	if err != nil || ack.Apps != 0 || f.Totals().Apps["reused"] != (Bytes{7, 11}) {
		t.Fatal("old snapshot consumed a replacement identity", ack, err)
	}
}

func TestRetainedLineChurnIsBoundedWithoutDiscardingBytes(t *testing.T) {
	l := Defaults()
	l.AccountingLines = 2
	f := New(l, nil)
	apply := func(n uint64, line string) {
		c := policy.Config{Lines: []platform.Line{{ID: line}}}
		if _, err := f.Apply(policy.Revision{N: n, Config: c, Hash: policy.Hash(c)}); err != nil {
			t.Fatal(err)
		}
	}
	apply(1, "old-a")
	x := admit(t, f, "tcp", "app")
	x.Add(1, 2)
	x.Close()
	apply(2, "old-b")
	x = admit(t, f, "udp", "app")
	x.Add(3, 4)
	x.Close()
	apply(3, "current")
	x, err := f.Begin("udp", tuple)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := x.Resolve(platform.Owner{AppID: "app"}); err != ErrAccounting {
		t.Fatal(err)
	}
	x.Close()
	page, err := f.PageTotals("")
	if err != nil {
		t.Fatal(err)
	}
	if page.Lines["old-a"].Bytes != (Bytes{1, 2}) || page.Lines["old-b"].Bytes != (Bytes{3, 4}) {
		t.Fatal("line churn discarded unread accounting", page)
	}
	ack, err := f.AckTotals(page.Receipt)
	if err != nil || ack.Lines != 2 {
		t.Fatal(ack, err)
	}
	x = admit(t, f, "udp", "app")
	x.Add(5, 6)
	x.Close()
	page, err = f.PageTotals("")
	if err != nil || page.Lines["current"].Bytes != (Bytes{5, 6}) {
		t.Fatal(page, err)
	}
	if _, err := f.AckTotals(page.Receipt); err != nil {
		t.Fatal(err)
	}
	if f.Totals().Lines["current"] != (Bytes{5, 6}) {
		t.Fatal("configured line lost its cumulative counter")
	}
}

func TestLongAccountingChurnStaysBoundedAndExact(t *testing.T) {
	l := Defaults()
	l.AccountingApps = 1024
	f := table(t, l)
	runtime.GC()
	var baseline runtime.MemStats
	runtime.ReadMemStats(&baseline)
	var consumedUp, consumedDown uint64
	var peak uint64
	const rounds = 100
	for round := range rounds {
		for i := range l.AccountingApps {
			id := fmt.Sprintf("%08d%s", round*l.AccountingApps+i, strings.Repeat("x", 504))
			x := admit(t, f, "tcp", id)
			x.Add(3, 7)
			x.Close()
		}
		cursor, receipt := "", ""
		entries := 0
		for {
			page, err := f.PageTotals(cursor)
			if err != nil {
				t.Fatal(round, err)
			}
			for _, b := range page.Apps {
				consumedUp += b.Up
				consumedDown += b.Down
				entries++
			}
			receipt = page.Receipt
			if page.Cursor == "" {
				break
			}
			cursor = page.Cursor
		}
		if entries != l.AccountingApps {
			t.Fatal("churn lost a generated identity", round, entries)
		}
		if _, err := f.AckTotals(receipt); err != nil {
			t.Fatal(err)
		}
		if len(f.totals.Apps) != 0 || len(f.accountingIDs) > 2 || f.Stats().SnapshotBytes != 0 {
			t.Fatal("acknowledged identities or snapshots retained", round)
		}
		if round%10 == 0 || round == rounds-1 {
			runtime.GC()
			var memory runtime.MemStats
			runtime.ReadMemStats(&memory)
			peak = max(peak, memory.HeapAlloc)
		}
	}
	if consumedUp != rounds*uint64(l.AccountingApps)*3 || consumedDown != rounds*uint64(l.AccountingApps)*7 {
		t.Fatal("generated bytes differ from client-consumed bytes", consumedUp, consumedDown)
	}
	if peak > baseline.HeapAlloc+8<<20 {
		t.Fatalf("retained heap grew across churn: baseline=%d peak=%d", baseline.HeapAlloc, peak)
	}
	t.Logf("ACCOUNTING_CHURN unique_apps=%d retained_limit=%d consumed_up=%d consumed_down=%d heap_after_gc_baseline=%d heap_after_gc_peak=%d", rounds*l.AccountingApps, l.AccountingApps, consumedUp, consumedDown, baseline.HeapAlloc, peak)
	runtime.KeepAlive(f)
}
