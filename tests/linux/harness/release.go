package harness

import (
	"fmt"
	"strings"
)

// CheckRelease checks the complete source registry, not a filtered run or a
// fortunate sample. Removing a declared blocker is a separate reviewed change.
func CheckRelease(cases []*Case) error {
	if len(cases) == 0 {
		return fmt.Errorf("release gate has no cases")
	}
	if err := Validate(cases); err != nil {
		return err
	}
	var blocked []string
	for _, c := range cases {
		if c.Label == Pending {
			blocked = append(blocked, c.ID+": pending: "+c.Waits)
		}
		if c.ReleaseBlocker != "" {
			blocked = append(blocked, c.ID+": release-blocker: "+c.ReleaseBlocker)
		}
	}
	if len(blocked) != 0 {
		return fmt.Errorf("release blocked by %d unfinished gates:\n%s", len(blocked), strings.Join(blocked, "\n"))
	}
	return nil
}
