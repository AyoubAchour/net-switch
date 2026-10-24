package control

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/AyoubAchour/net-switch/internal/control/engine"
	"github.com/AyoubAchour/net-switch/internal/usage"
)

// totalsEvery is how often Control reads the engine's exact accounting.
const totalsEvery = 5000

// totalsBudget bounds one complete read. The engine keeps a totals snapshot
// for ten seconds; a read that cannot finish inside it is discarded whole.
const totalsBudget = 10 * time.Second

// scheduleTotals starts one accounting read in the background when the engine
// offers paged totals and the previous read has finished.
func (c *Core) scheduleTotals(ctx context.Context, gen uint64) {
	accounting, ok := c.op.Engine.(engine.Accounting)
	if !ok {
		return
	}
	c.mu.Lock()
	due := !c.totalsBusy && c.now()-c.totalsAt >= totalsEvery
	if due {
		c.totalsBusy = true
	}
	c.mu.Unlock()
	if !due {
		return
	}
	c.op.Background(func() {
		defer func() {
			c.mu.Lock()
			c.totalsBusy = false
			c.totalsAt = c.now()
			c.mu.Unlock()
		}()
		if err := c.readTotals(ctx, accounting, gen); err != nil && !errors.Is(err, engine.ErrNoAccounting) {
			c.log("engine accounting not consumed this round: %v", err)
		}
	})
}

// readTotals is spec §5.10's production consumer. Every page of one receipt is
// absorbed into the routed-usage record; that record is written durably; only
// then is the receipt acknowledged, so the engine retires nothing Control has
// not already kept. A lost acknowledgement is retried with the same opId.
func (c *Core) readTotals(ctx context.Context, accounting engine.Accounting, gen uint64) error {
	ctx, cancel := context.WithTimeout(ctx, totalsBudget)
	defer cancel()
	cursor, receipt, instance := "", "", ""
	seen := map[string]bool{}
	apps, lines := map[string]bool{}, map[string]bool{}
	pages := []engine.TotalsPage{}
	for {
		page, err := accounting.Totals(ctx, cursor)
		if err != nil {
			return err
		}
		if receipt == "" {
			receipt, instance = page.Receipt, page.Instance
		} else if page.Receipt != receipt || page.Instance != instance {
			return errors.New("totals pages changed receipt or instance mid-read")
		}
		if receipt == "" || instance == "" {
			return errors.New("totals page has no receipt or instance")
		}
		for id := range page.Apps {
			apps[id] = true
		}
		for id := range page.Lines {
			lines[id] = true
		}
		pages = append(pages, page)
		if page.Cursor == "" {
			break
		}
		if seen[page.Cursor] || (len(page.Apps) == 0 && len(page.Lines) == 0) {
			return errors.New("totals cursor made no progress")
		}
		seen[page.Cursor] = true
		cursor = page.Cursor
	}
	c.mu.Lock()
	if gen != c.generation {
		c.mu.Unlock()
		return nil
	}
	if c.usage.Routed == nil {
		c.usage.Routed = usage.NewRouted()
	}
	changed := false
	for _, page := range pages {
		changed = c.usage.Routed.Absorb(instance, routedCounters(page.Apps), routedCounters(page.Lines)) || changed
	}
	changed = c.usage.Routed.Compact(apps, lines) || changed
	if changed {
		c.routedGeneration++
	}
	// Dirty means an earlier commit failed or this read changed something. An
	// unchanged read after a failed commit must still write before it acks.
	dirty := c.routedGeneration != c.routedSaved
	c.mu.Unlock()
	if dirty {
		if err := c.SaveUsage(); err != nil {
			return fmt.Errorf("routed usage not committed; accounting left unacknowledged: %w", err)
		}
	}
	c.checkpoint("control-after-usage-commit")
	opID := "ack-" + receipt
	var err error
	for attempt := 0; attempt < 3; attempt++ {
		if err = accounting.AckTotals(ctx, opID, receipt); err == nil {
			break
		}
		if ctx.Err() != nil {
			break
		}
	}
	if err != nil {
		return fmt.Errorf("accounting acknowledgement %s failed; the next full read is safe: %w", opID, err)
	}
	c.checkpoint("control-after-totals-ack")
	return nil
}

func routedCounters(in map[string]engine.Counter) map[string]usage.RoutedCounter {
	out := make(map[string]usage.RoutedCounter, len(in))
	for id, v := range in {
		out[id] = usage.RoutedCounter{Up: v.Up, Down: v.Down, Generation: v.Generation}
	}
	return out
}
