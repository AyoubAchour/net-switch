package lifecycle

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/AyoubAchour/net-switch/internal/journal"
)

// standInRefusal is the message for a data folder written by the pre-release
// stand-in build. Nothing outside CI and the owner's own test installs ever
// had one, so there is no migration: the folder is retired by hand.
const standInRefusal = "this data folder belonged to a pre-release stand-in build (sing-box adapter); run that build's uninstall or remove the folder, then install again"

// refuseStandInStore rejects a store holding stand-in state: an engine-state
// record without the native schema, or journal records of the stand-in's
// adapter scopes. Both the installer and the native host call it, so the
// native engine never starts over state it cannot interpret.
func refuseStandInStore(data string) error {
	b, err := os.ReadFile(filepath.Join(data, "engine-state.json"))
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	if err == nil {
		var record struct {
			Schema int `json:"schema"`
		}
		if json.Unmarshal(b, &record) != nil || record.Schema != 1 {
			return fmt.Errorf("%s: engine-state.json has no native schema", standInRefusal)
		}
	}
	store := &journal.FileStore{Path: filepath.Join(data, "engine-journal.json")}
	records, err := store.Records()
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	for _, r := range records {
		if r.Kind == "adapter-service-scope" || r.Kind == "adapter-linux-rule" {
			return fmt.Errorf("%s: engine-journal.json holds %q records", standInRefusal, r.Kind)
		}
	}
	return nil
}
