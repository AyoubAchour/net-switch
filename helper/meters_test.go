package main

import (
	"encoding/json"
	"testing"
)

func TestMeterLinesKeepThePowerShellShape(t *testing.T) {
	got, _ := json.Marshal(metersLine{Adapters: []adapterReading{{Alias: "Ethernet", RX: 123, TX: 456}, {Alias: "Wi-Fi", RX: 0, TX: 0}}})
	if string(got) != `{"adapters":[{"alias":"Ethernet","rx":123,"tx":456},{"alias":"Wi-Fi","rx":0,"tx":0}]}` {
		t.Errorf("got %s", got)
	}
	// No adapters is an empty list, not null.
	got, _ = json.Marshal(metersLine{Adapters: []adapterReading{}})
	if string(got) != `{"adapters":[]}` {
		t.Errorf("got %s", got)
	}
}
