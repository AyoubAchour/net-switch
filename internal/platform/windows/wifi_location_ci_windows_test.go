package winplatform

import (
	"flag"
	"fmt"
	"os"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

var wifiLocationMode = flag.String("wifi-location-mode", "", "CI-only network reader or legacy location positive control")

// Runs only when explicitly selected by the hosted-runner proof script.
// Ordinary go test never reads the network or invokes the old Wi-Fi API here.
func TestWiFiLocationProbeCI(t *testing.T) {
	if *wifiLocationMode == "" {
		t.Skip("hosted-runner privacy probe only")
	}
	if os.Getenv("GITHUB_ACTIONS") != "true" {
		t.Fatal("privacy probes must run in CI, never on the owner's PC")
	}
	switch *wifiLocationMode {
	case "reader":
		line, err := readNetwork()
		if err != nil {
			t.Fatal(err)
		}
		names := 0
		for _, adapter := range line.Adapters {
			if adapter.SSID != nil {
				names++
			}
		}
		t.Logf("WIFI_READER adapters=%d names=%d", len(line.Adapters), names)
	case "legacy":
		legacyLocationControl(t)
	default:
		t.Fatalf("unknown privacy probe mode %q", *wifiLocationMode)
	}
}

// Independent, test-only reproduction of the documented location-sensitive
// call. It is not linked into netswitch.exe. It never scans or changes Wi-Fi.
func legacyLocationControl(t *testing.T) {
	dll := windows.NewLazySystemDLL("wlanapi.dll")
	open := dll.NewProc("WlanOpenHandle")
	if err := open.Find(); err != nil {
		t.Logf("WIFI_CONTROL_UNAVAILABLE %v", err)
		return
	}
	var version uint32
	var handle windows.Handle
	code, _, _ := open.Call(2, 0, uintptr(unsafe.Pointer(&version)), uintptr(unsafe.Pointer(&handle)))
	if code != 0 {
		t.Logf("WIFI_CONTROL_UNAVAILABLE WlanOpenHandle=%d (WLAN service/feature may be absent)", code)
		return
	}
	defer dll.NewProc("WlanCloseHandle").Call(uintptr(handle), 0)
	type wlanInterface struct {
		ID          windows.GUID
		Description [256]uint16
		State       uint32
	}
	type interfaceList struct {
		Count, Index uint32
		Items        [1]wlanInterface
	}
	if unsafe.Offsetof(interfaceList{}.Items) != 8 || unsafe.Sizeof(wlanInterface{}) != 532 {
		t.Fatal("incorrect WLAN SDK layout")
	}
	var list *interfaceList
	code, _, _ = dll.NewProc("WlanEnumInterfaces").Call(uintptr(handle), 0, uintptr(unsafe.Pointer(&list)))
	if code != 0 {
		t.Logf("WIFI_CONTROL_UNAVAILABLE WlanEnumInterfaces=%d", code)
		return
	}
	defer dll.NewProc("WlanFreeMemory").Call(uintptr(unsafe.Pointer(list)))
	attempts := 0
	for _, item := range unsafe.Slice(&list.Items[0], list.Count) {
		if item.State != 1 {
			continue
		}
		attempts++
		var size, kind uint32
		var data unsafe.Pointer
		code, _, _ := dll.NewProc("WlanQueryInterface").Call(uintptr(handle), uintptr(unsafe.Pointer(&item.ID)), 7, 0,
			uintptr(unsafe.Pointer(&size)), uintptr(unsafe.Pointer(&data)), uintptr(unsafe.Pointer(&kind)))
		if data != nil {
			dll.NewProc("WlanFreeMemory").Call(uintptr(data))
		}
		t.Logf("WIFI_CONTROL_QUERY opcode=7 result=%d", code)
	}
	if attempts == 0 {
		t.Log("WIFI_CONTROL_UNAVAILABLE no connected Wi-Fi adapter")
	}
	fmt.Printf("WIFI_CONTROL_ATTEMPTS=%d\n", attempts)
}
