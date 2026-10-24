package usage

import (
	"encoding/json"
	"strconv"
	"testing"
)

func TestRoutedAbsorbCountsEachGenerationOnce(t *testing.T) {
	r := NewRouted()
	page := map[string]RoutedCounter{"app": {Up: 100, Down: 200, Generation: "1"}}
	if !r.Absorb("i1", page, nil) || r.Apps["app"].Up != 100 || r.Apps["app"].Down != 200 {
		t.Fatal("first page not absorbed", r.Apps["app"])
	}
	// A repeated read of the same counters (a crash between commit and ack)
	// adds nothing.
	if r.Absorb("i1", page, nil) || r.Apps["app"].Up != 100 {
		t.Fatal("same generation counted twice", r.Apps["app"])
	}
	// Growth within the generation adds the difference only.
	r.Absorb("i1", map[string]RoutedCounter{"app": {Up: 150, Down: 200, Generation: "1"}}, nil)
	if r.Apps["app"].Up != 150 || r.Apps["app"].Down != 200 {
		t.Fatal("delta not applied", r.Apps["app"])
	}
	// A new generation (retired after an ack, then seen again) starts at zero.
	r.Absorb("i1", map[string]RoutedCounter{"app": {Up: 7, Down: 9, Generation: "2"}}, nil)
	if r.Apps["app"].Up != 157 || r.Apps["app"].Down != 209 {
		t.Fatal("new generation not added whole", r.Apps["app"])
	}
	// A new engine instance restarts every counter at zero.
	r.Absorb("i2", map[string]RoutedCounter{"app": {Up: 1, Down: 1, Generation: "1"}}, nil)
	if r.Apps["app"].Up != 158 || r.Apps["app"].Down != 210 || r.Instance != "i2" {
		t.Fatal("instance change mishandled", r.Apps["app"], r.Instance)
	}
}

func TestRoutedCompactFoldsOnlyAbsentIdentities(t *testing.T) {
	r := NewRouted()
	page := map[string]RoutedCounter{"present": {Up: 1, Generation: "1"}}
	for i := 0; i < RoutedKeep+10; i++ {
		page["app-"+strconv.Itoa(i)] = RoutedCounter{Up: uint64(i + 1), Generation: "1"}
	}
	r.Absorb("i1", page, nil)
	present := map[string]bool{"present": true}
	if !r.Compact(present, nil) {
		t.Fatal("nothing folded")
	}
	if _, ok := r.Apps["present"]; !ok {
		t.Fatal("a present identity was folded")
	}
	// The ten smallest absent entries (1..10 bytes) fold into Other.
	if r.Folded != 10 || len(r.Apps) != RoutedKeep+1 || r.Other.Up != 55 {
		t.Fatal("fold count or remainder wrong", r.Folded, len(r.Apps), r.Other)
	}
	if r.Compact(present, nil) {
		t.Fatal("a second compaction changed a bounded set")
	}
}

func TestRoutedRoundTripsThroughUsageFile(t *testing.T) {
	u := New(nil)
	u.Routed = NewRouted()
	u.Routed.Absorb("i1", map[string]RoutedCounter{"app": {Up: 5, Down: 6, Generation: "g"}}, map[string]RoutedCounter{"line": {Up: 1, Generation: "h"}})
	// Beyond 2^53 a float64 would round; the routed section must stay exact.
	u.Routed.Apps["app"].Up = 1<<60 + 3
	b, err := json.Marshal(u.Saved)
	if err != nil {
		t.Fatal(err)
	}
	again := LoadRouted(b)
	if again == nil || *again.Apps["app"] != *u.Routed.Apps["app"] || *again.Lines["line"] != *u.Routed.Lines["line"] || again.Instance != "i1" {
		t.Fatalf("routed usage lost or rounded on reload: %+v", again)
	}
	if LoadRouted([]byte(`{"lines":{},"peaks":{}}`)) != nil || LoadRouted([]byte(`not json`)) != nil {
		t.Fatal("an adapter-era or invalid record grew a routed section")
	}
	plain := New(nil)
	plain.Load(map[string]any{"lines": map[string]any{}})
	if b, _ := json.Marshal(plain.Saved); string(b) != `{"lines":{},"peaks":{}}` {
		t.Fatal("adapter-era usage record changed shape", string(b))
	}
}
