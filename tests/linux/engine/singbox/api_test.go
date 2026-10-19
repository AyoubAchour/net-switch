package singbox

import (
	"testing"

	"github.com/AyoubAchour/net-switch/tests/linux/engine"
)

func TestCleanProcessPath(t *testing.T) {
	cases := map[string]string{
		"/opt/nsapps/bravo/nsapp (runner)":           "/opt/nsapps/bravo/nsapp",
		"/opt/nsapps/bravo/nsapp (deleted) (runner)": "/opt/nsapps/bravo/nsapp",
		"/opt/nsapps/bravo/nsapp (deleted)":          "/opt/nsapps/bravo/nsapp",
		"/usr/bin/curl":                              "/usr/bin/curl",
		"/opt/My App (x86)/run (root)":               "/opt/My App (x86)/run",
		"":                                           "",
	}
	for in, want := range cases {
		if got := CleanProcessPath(in); got != want {
			t.Errorf("CleanProcessPath(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestRuleFingerprint(t *testing.T) {
	running := "31102:\tfrom all iif NetSwitch goto 31110"
	crashed := "31102:\tfrom all iif NetSwitch [detached] goto 31110 [unresolved]"
	if RuleFingerprint(running) != RuleFingerprint(crashed) {
		t.Fatalf("%q and %q are the same rule", RuleFingerprint(running), RuleFingerprint(crashed))
	}
	if got := RuleFingerprint(crashed); got != "31102: from all iif NetSwitch goto 31110" {
		t.Fatalf("got %q", got)
	}
	if RuleFingerprint("31100:\tfrom all lookup 3110") == RuleFingerprint("31101:\tfrom all lookup 3110") {
		t.Fatal("different priorities are different rules")
	}
}

func TestParseConnections(t *testing.T) {
	data := []byte(`{"downloadTotal":1,"uploadTotal":2,"connections":[
	 {"id":"x1","metadata":{"network":"tcp","sourceIP":"198.18.0.1","sourcePort":"40000","destinationIP":"198.51.100.10","destinationPort":"7002","processPath":"/opt/nsapps/bravo/nsapp (runner)"},
	  "upload":10,"download":20,"start":"2026-10-19T10:00:00.5Z","chains":["line-c","lane-b"]},
	 {"id":"x2","metadata":{"network":"udp","sourceIP":"198.18.0.1","sourcePort":"5353","destinationIP":"::ffff:198.51.100.10","destinationPort":"7001","processPath":""},
	  "upload":0,"download":0,"start":"2026-10-19T10:00:01Z","chains":["line-a"]}]}`)
	flows, err := ParseConnections(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(flows) != 2 {
		t.Fatalf("got %d flows", len(flows))
	}
	f := flows[0]
	if f.Line != "c" || f.Lane != "b" || f.App != "/opt/nsapps/bravo/nsapp" || f.Protocol != "tcp" || f.Destination.Port() != 7002 || f.Down != 20 {
		t.Errorf("flow 1: %+v", f)
	}
	if g := flows[1]; g.Line != "a" || g.Lane != "a" || g.Destination.Addr().String() != "198.51.100.10" {
		t.Errorf("flow 2: %+v", g)
	}
	if !Matches(engine.Selector{Line: "c"}, f) || Matches(engine.Selector{Line: "a"}, f) {
		t.Error("line selector")
	}
	if !Matches(engine.Selector{App: f.App, NotLine: "a"}, f) || Matches(engine.Selector{App: f.App, NotLine: "c"}, f) {
		t.Error("reconnect selector")
	}
	if Matches(engine.Selector{}, f) {
		t.Error("an empty selector must match nothing")
	}
}
