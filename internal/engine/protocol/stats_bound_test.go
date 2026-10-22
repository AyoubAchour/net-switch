package protocol

import (
	"encoding/json"
	"strings"
	"testing"
)

// A stats map larger than one reply loses its largest sections, named with
// their sizes, and keeps everything else; one under budget is sent whole.
func TestBoundStatsLeavesOutTheLargestSectionsByName(t *testing.T) {
	small := map[string]any{"flows": map[string]int{"Flows": 3}, "heapBytes": 1}
	if raw, ok := boundStats(small).(json.RawMessage); !ok || !strings.Contains(string(raw), `"heapBytes":1`) {
		t.Fatalf("a small reply changed: %v", boundStats(small))
	}
	big := map[string]any{"flows": map[string]int{"Flows": 3}, "heapBytes": 1,
		"nativeSocketState": strings.Repeat("s", 900<<10), "packetTrace": strings.Repeat("p", 400<<10), "nativeUDPState": strings.Repeat("u", 64<<10)}
	bounded, ok := boundStats(big).(map[string]any)
	if !ok {
		t.Fatalf("an oversized reply was not bounded: %T", boundStats(big))
	}
	omitted := bounded["omittedForSize"].(map[string]int)
	if _, gone := bounded["nativeSocketState"]; gone || omitted["nativeSocketState"] < 900<<10 || bounded["packetTrace"] == nil ||
		bounded["nativeUDPState"] == nil || bounded["flows"] == nil || len(omitted) != 1 {
		t.Fatalf("kept %d sections, omitted %v", len(bounded), omitted)
	}
	b, err := json.Marshal(Reply{ID: strings.Repeat("i", 128), Result: map[string]any{"engine": bounded, "eventsDropped": uint64(1 << 63)}})
	if err != nil || len(b)+1 > MessageLimit {
		t.Fatalf("bounded reply is %d bytes of %d: %v", len(b), MessageLimit, err)
	}
	if _, isBig := big["nativeSocketState"]; !isBig {
		t.Fatal("the runtime's own map was changed")
	}
}
