package winengine

import (
	"slices"

	"github.com/AyoubAchour/net-switch/internal/engine/flows"
	"github.com/AyoubAchour/net-switch/internal/engine/platform"
)

func retainLineSelectors(wanted, previous []platform.Line, table *flows.Table) []platform.Line {
	result := slices.Clone(wanted)
	ids := make(map[string]bool, len(wanted))
	for _, line := range wanted {
		ids[line.ID] = true
	}
	if table != nil {
		for _, line := range previous {
			if !ids[line.ID] && table.ReferencesLine(line.ID) {
				result = append(result, line)
			}
		}
	}
	return result
}
