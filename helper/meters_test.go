package main

import (
	"encoding/json"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

func TestMibIfRow2MatchesTheWindowsLayout(t *testing.T) {
	// sizeof(MIB_IF_ROW2) on 64-bit Windows.
	if size := unsafe.Sizeof(windows.MibIfRow2{}); size != 1352 {
		t.Errorf("MIB_IF_ROW2 is %d bytes, want 1352", size)
	}
}

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
