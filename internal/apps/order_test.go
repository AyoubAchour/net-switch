package apps

import (
	"reflect"
	"testing"
)

func TestConnectionOrderAndZeroRetention(t *testing.T) {
	tracker := NewTracker(0)
	connections := []Connection{{ID: "first", Chains: []string{"line-a1"}}, {ID: "second", Chains: []string{"line-123456"}}, {ID: "third", Chains: []string{"line-012345"}}}
	tracker.Ingest(connections, 1000)
	if got := tracker.ConnectionIDsOffLine("unknown", "other"); !reflect.DeepEqual(got, []string{"second", "first", "third"}) {
		t.Fatalf("connection order: %v", got)
	}
	tracker.Ingest(nil, 1001)
	if len(tracker.Snapshot(nil)) != 0 {
		t.Fatal("explicit zero retention kept an idle app")
	}
}
