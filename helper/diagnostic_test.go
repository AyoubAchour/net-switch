package main

import (
	"strings"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

func TestRunnerInterfaces(t *testing.T) {
	hidden, err := hiddenAdapters()
	if err != nil {
		t.Fatal(err)
	}
	var table *windows.MibIfTable2
	if err := windows.GetIfTable2Ex(windows.MibIfTableNormal, &table); err != nil {
		t.Fatal(err)
	}
	defer windows.FreeMibTable(unsafe.Pointer(table))
	for _, row := range unsafe.Slice(&table.Table[0], table.NumEntries) {
		ipif := windows.MibIpInterfaceRow{Family: windows.AF_INET, InterfaceIndex: row.InterfaceIndex}
		err := windows.GetIpInterfaceEntry(&ipif)
		t.Logf("GetIfTable2 alias=%q guid=%s index=%d type=%d flags=0x%02x oper=%d hiddenOrPhantom=%t IPv4Error=%v", windows.UTF16ToString(row.Alias[:]), row.InterfaceGuid.String(), row.InterfaceIndex, row.Type, row.InterfaceAndOperStatusFlags, row.OperStatus, hidden[strings.ToLower(row.InterfaceGuid.String())], err)
	}
}
