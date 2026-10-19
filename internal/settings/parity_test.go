package settings

import (
	"github.com/AyoubAchour/net-switch/internal/apps"
	"math"
	"strings"
	"testing"
)

func TestPinOrderSurvivesChangesAndReload(t *testing.T) {
	s := New(t.TempDir(), Options{})
	const old = `C:\Discord\app-1.0.9\Discord.exe`
	const newer = `C:\Discord\app-1.0.10\Discord.exe`
	update(t, s, map[string]any{"appLines": apps.Pins{{Path: old, LineID: "a1"}, {Path: newer, LineID: "b2"}}})
	load(t, s)
	_, err := s.Change(func(v map[string]any) map[string]any {
		p := v["appLines"].(apps.Pins)
		p.Set(`C:\Other.exe`, "a1")
		return map[string]any{"appLines": p}
	})
	if err != nil {
		t.Fatal(err)
	}
	pins := load(t, s)["appLines"].(apps.Pins)
	require(t, pins[0].Path == old && pins[1].Path == newer)
	rows := apps.NewTracker().Snapshot(pins)
	require(t, rows[0].Line != nil && *rows[0].Line == "b2")
	require(t, read(t, s.File) == read(t, s.File+".bak"))
	_, err = s.Update(map[string]any{"appLines": map[string]string{old: "a1", newer: "b2"}})
	require(t, err != nil && strings.Contains(err.Error(), "apps.Pins"))
}

func TestRecoveryReasonUsesDefaultOrder(t *testing.T) {
	s := New(t.TempDir(), Options{})
	write(t, s.File, `{"checkForUpdates":1,"combine":null,"lines":false,"appLines":[]}`)
	for i := 0; i < 30; i++ {
		load(t, s)
		require(t, s.Recovery.Reason == "Invalid types reset to defaults: lines, appLines, combine, checkForUpdates.")
	}
}

func TestJSONNumberSemantics(t *testing.T) {
	s := New(t.TempDir(), Options{})
	write(t, s.File, `{"unknown":{"huge":1e400},"combine":true}`)
	v := load(t, s)
	require(t, s.Recovery == nil && math.IsInf(v["unknown"].(map[string]any)["huge"].(float64), 1))
	update(t, s, map[string]any{"numbers": []float64{math.NaN(), math.Inf(1), math.Inf(-1), math.Copysign(0, -1)}, "text": "&<>"})
	text := read(t, s.File)
	require(t, !strings.Contains(text, "-0") && !strings.Contains(text, `\u003c`) && strings.Contains(text, "&<>"))
	nums := load(t, s)["numbers"].([]any)
	require(t, nums[0] == nil && nums[1] == nil && nums[2] == nil && nums[3] == float64(0))
	write(t, s.File, `{} {}`)
	load(t, s)
	require(t, s.Recovery != nil && s.Recovery.SavedAs != nil)
}
