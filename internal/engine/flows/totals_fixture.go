//go:build lifecycle_test

package flows

import (
	"errors"
	"fmt"
	"strings"
)

// SeedAccountingFixture populates legitimate closed-counter rows only in the
// hosted fault build. This measures the actual transport at retained capacity,
// not socket capacity or process lookup. No product method can call it.
func (t *Table) SeedAccountingFixture() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.policy == nil {
		return ErrStopped
	}
	for i := 0; len(t.totals.Apps) < AccountingEntries || len(t.totals.Lines) < AccountingEntries; i++ {
		app := fmt.Sprintf("fixture-app-%08d%s", i, strings.Repeat("x", 492))
		line := fmt.Sprintf("fixture-line-%08d%s", i, strings.Repeat("x", 43))
		if len(t.totals.Apps) >= AccountingEntries {
			for id := range t.totals.Apps {
				app = id
				break
			}
		}
		if len(t.totals.Lines) >= AccountingEntries {
			for id := range t.totals.Lines {
				line = id
				break
			}
		}
		if !t.reserveAccounting(app, line) {
			return errors.New("accounting fixture could not reach retained capacity")
		}
		fold(t.totals.Apps, app, 3, 7)
		fold(t.totals.Lines, line, 3, 7)
	}
	return nil
}
