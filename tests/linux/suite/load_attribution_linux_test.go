//go:build linux

package suite

import (
	"testing"

	"github.com/AyoubAchour/net-switch/tests/linux/engine"
)

func TestLoadAttributionNeverWaivesIdentityOrRoutingErrors(t *testing.T) {
	path := AppPath("bravo")
	known := engine.Flow{App: path, AppID: path, PID: 42, Lane: "b", Line: "b"}
	unknown := engine.Flow{Lane: "a", Line: "a"}
	for _, test := range []struct {
		name         string
		flow         engine.Flow
		line         engine.LineID
		known, valid bool
	}{
		{"identified on pinned line", known, "b", true, true},
		{"explicit unknown on main", unknown, "a", false, true},
		{"identified on main is still wrong", engine.Flow{App: path, AppID: path, PID: 42, Lane: "a", Line: "a"}, "b", true, false},
		{"unknown on pinned line is still wrong", engine.Flow{Lane: "b", Line: "b"}, "a", false, false},
		{"wrong app", engine.Flow{App: AppPath("alpha"), AppID: AppPath("alpha"), PID: 42, Lane: "b", Line: "b"}, "b", true, false},
		{"wrong pid", engine.Flow{App: path, AppID: path, PID: 43, Lane: "b", Line: "b"}, "b", true, false},
		{"partial unknown", engine.Flow{AppID: path, Lane: "a", Line: "a"}, "a", false, false},
		{"wrong selector", engine.Flow{App: path, AppID: path, PID: 42, Lane: "c", Line: "b"}, "b", true, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			line, identified, err := loadFlowLine(test.flow, path, 42, "b")
			if line != test.line || identified != test.known || (err == nil) != test.valid {
				t.Fatalf("line=%s identified=%t error=%v", line, identified, err)
			}
		})
	}
}
