package winplatform

import (
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
