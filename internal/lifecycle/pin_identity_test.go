package lifecycle

import (
	"testing"

	"github.com/AyoubAchour/net-switch/internal/apppath"
	"github.com/AyoubAchour/net-switch/internal/apps"
	ce "github.com/AyoubAchour/net-switch/internal/control/engine"
	"github.com/AyoubAchour/net-switch/internal/engine/platform"
	"github.com/AyoubAchour/net-switch/internal/engine/policy"
)

// decide compiles Control's revision for the given platform rules and asks the
// engine's own policy which line a flow from owner takes: the real routing
// decision, not just the compiled keys.
func decide(t *testing.T, rev ce.Revision, rules apppath.Rules, owner platform.Owner) string {
	t.Helper()
	native, err := nativeRevisionWith(rev, rules)
	if err != nil {
		t.Fatal(err)
	}
	compiled, err := policy.Compile(native)
	if err != nil {
		t.Fatal(err)
	}
	d, err := compiled.Decide(owner, 40000, false, 0)
	if err != nil {
		t.Fatal(err)
	}
	return d.Line
}

// Spec §5.4: rules match on the engine's app identity, and a pin stores the
// identity the person selected. Every case below is the engine's decision.
func TestPinsRouteByTheEnginesIdentity(t *testing.T) {
	base := testRevision(1)
	base.Policy.Combine, base.Policy.Shares = false, nil
	base.Policy.Lanes = map[string]string{"a1": "a1", "b2": "b2", "c3": "c3"}
	base.Policy.Blocked = nil
	with := func(pins ...apps.Pin) ce.Revision {
		r := base
		r.Policy.AppLines = apps.Pins(pins)
		return r
	}
	// Windows: a 0.3.x path pin is the engine's identity (the normalised path),
	// so it routes exactly as today, whatever the case the process reports.
	win := with(apps.Pin{Path: `C:\Games\Game.exe`, LineID: "b2"})
	if line := decide(t, win, apppath.Windows, platform.Owner{Path: `c:\games\GAME.EXE`, AppID: apppath.Key(`c:\games\GAME.EXE`)}); line != "b2" {
		t.Fatal("Windows path pin stopped routing", line)
	}
	if line := decide(t, win, apppath.Windows, platform.Owner{Path: `C:\Other\App.exe`, AppID: apppath.Key(`C:\Other\App.exe`)}); line != "a1" {
		t.Fatal("unpinned Windows app left the main line", line)
	}
	// Linux plain executable: the pin is the case-preserving Linux identity.
	plain := with(apps.Pin{Path: "/opt/Game/Game", LineID: "b2"})
	if line := decide(t, plain, apppath.Linux, platform.Owner{Path: "/opt/Game/Game", AppID: apppath.Normalize("/opt/Game/Game", apppath.Linux)}); line != "b2" {
		t.Fatal("plain Linux pin stopped routing", line)
	}
	if line := decide(t, plain, apppath.Linux, platform.Owner{Path: "/opt/game/game", AppID: apppath.Normalize("/opt/game/game", apppath.Linux)}); line != "a1" {
		t.Fatal("Linux identity folded case", line)
	}
	// A Snap pin created from the tracked app stores "snap:foo" and routes
	// the process the engine reports under that identity.
	snap := with(apps.Pin{Path: "snap:foo", LineID: "c3"})
	if line := decide(t, snap, apppath.Linux, platform.Owner{Path: "/snap/foo/123/bin/foo", AppID: "snap:foo"}); line != "c3" {
		t.Fatal("snap identity pin did not route", line)
	}
	// A stored *path* pin for a sandboxed app cannot name the process (the
	// engine reports snap:foo): it is flagged for reselection, compiled to
	// nothing, and the flow keeps the default decision rather than a guess.
	stale := with(apps.Pin{Path: "/snap/foo/123/bin/foo", LineID: "c3"})
	if !apps.PinNeedsReselection(stale.Policy.AppLines[0], "snap:foo") || !apps.PinNeedsReselection(stale.Policy.AppLines[0], "") {
		t.Fatal("sandbox path pin not flagged for reselection")
	}
	if line := decide(t, stale, apppath.Linux, platform.Owner{Path: "/snap/foo/123/bin/foo", AppID: "snap:foo"}); line != "a1" {
		t.Fatal("stale sandbox path pin routed by guess", line)
	}
	if native, _ := nativeRevisionWith(stale, apppath.Linux); len(native.Config.AppLines) != 0 {
		t.Fatal("stale sandbox path pin reached the engine", native.Config.AppLines)
	}
	if apps.PinNeedsReselection(apps.Pin{Path: "/opt/Game/Game"}, "") || apps.PinNeedsReselection(apps.Pin{Path: "snap:foo"}, "snap:foo") {
		t.Fatal("a plain path pin or an identity pin was flagged")
	}
	// Two Flatpaks share /app/bin/game; only the selected identity is pinned.
	flatpak := with(apps.Pin{Path: "flatpak:org.example.Game", LineID: "b2"})
	if line := decide(t, flatpak, apppath.Linux, platform.Owner{Path: "/app/bin/game", AppID: "flatpak:org.example.Game"}); line != "b2" {
		t.Fatal("selected Flatpak did not route", line)
	}
	if line := decide(t, flatpak, apppath.Linux, platform.Owner{Path: "/app/bin/game", AppID: "flatpak:org.example.Other"}); line != "a1" {
		t.Fatal("the other Flatpak sharing the path was routed by the pin", line)
	}
	if line := decide(t, flatpak, apppath.Linux, platform.Owner{Path: "/app/bin/game", AppID: apppath.Normalize("/app/bin/game", apppath.Linux)}); line != "a1" {
		t.Fatal("a plain process at the shared path was routed by the pin", line)
	}
}
