package winplatform

import (
	"errors"
	"strings"
	"testing"
	"unsafe"
)

func TestDispatchPreservesUnderlyingHRESULT(t *testing.T) {
	var code uint32 = 0x80070002
	err := dispatchError("GetFolder", &comError{Code: 0x80020009}, int32(code), 0, "")
	if !missingCOM(err) {
		t.Fatalf("missing folder hidden by dispatch wrapper: %v", err)
	}
	var native *comError
	if !errors.As(err, &native) || native.Code != code {
		t.Fatal("underlying code lost")
	}
	if !strings.Contains(err.Error(), "GetFolder") || !strings.Contains(err.Error(), "80020009") {
		t.Fatal("diagnostic context lost")
	}
	if missingCOM(dispatchError("GetFolder", &comError{Code: 0x80070005}, 0, 0, "denied")) {
		t.Fatal("access denied treated as missing")
	}
}
func TestAutomationLayouts(t *testing.T) {
	if unsafe.Sizeof(variant{}) != 24 || unsafe.Sizeof(dispatchParams{}) != 24 || unsafe.Sizeof(exceptionInfo{}) != 64 || unsafe.Offsetof(exceptionInfo{}.scode) != 56 {
		t.Fatal("COM Automation ABI does not match the Windows SDK")
	}
}
