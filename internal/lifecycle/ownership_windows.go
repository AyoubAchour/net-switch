package lifecycle

import (
	"errors"
	"github.com/AyoubAchour/net-switch/internal/journal"
)

func adapterOwnership(Config, *journal.FileStore, string, string) func([]byte) ([]byte, error) {
	return nil
}
func removeAdapterRule(journal.Record) error { return errors.New("Linux rule record on Windows") }
