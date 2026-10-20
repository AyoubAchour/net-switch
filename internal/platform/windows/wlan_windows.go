package winplatform

import (
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

var wlan = windows.NewLazySystemDLL("wlanapi.dll")

type wlanInterface struct {
	GUID        windows.GUID
	Description [256]uint16
	State       uint32
}

type wlanInterfaceList struct {
	Count      uint32
	Index      uint32
	Interfaces [1]wlanInterface
}

type wlanConnection struct {
	State      uint32
	Mode       uint32
	Profile    [256]uint16
	SSIDLength uint32
	SSID       [32]byte
}

// Wi-Fi is optional, and Windows may refuse SSID access under its location
// privacy settings. Like netsh, that leaves SSID null, not the network offline.
func readSSIDs() map[string]string {
	result := map[string]string{}
	open := wlan.NewProc("WlanOpenHandle")
	if open.Find() != nil {
		return result
	}
	var version uint32
	var handle windows.Handle
	code, _, _ := open.Call(2, 0, uintptr(unsafe.Pointer(&version)), uintptr(unsafe.Pointer(&handle)))
	if code != 0 {
		return result
	}
	defer wlan.NewProc("WlanCloseHandle").Call(uintptr(handle), 0)
	var list *wlanInterfaceList
	code, _, _ = wlan.NewProc("WlanEnumInterfaces").Call(uintptr(handle), 0, uintptr(unsafe.Pointer(&list)))
	if code != 0 {
		return result
	}
	free := wlan.NewProc("WlanFreeMemory")
	defer free.Call(uintptr(unsafe.Pointer(list)))
	for _, item := range unsafe.Slice(&list.Interfaces[0], list.Count) {
		if item.State != 1 {
			continue
		}
		var size, kind uint32
		var connection *wlanConnection
		// wlan_intf_opcode_current_connection = 7.
		code, _, _ = wlan.NewProc("WlanQueryInterface").Call(uintptr(handle), uintptr(unsafe.Pointer(&item.GUID)), 7, 0,
			uintptr(unsafe.Pointer(&size)), uintptr(unsafe.Pointer(&connection)), uintptr(unsafe.Pointer(&kind)))
		if code == 0 {
			if size >= uint32(unsafe.Sizeof(wlanConnection{})) && connection.SSIDLength <= 32 {
				result[strings.ToLower(item.GUID.String())] = strings.TrimSpace(string(connection.SSID[:connection.SSIDLength]))
			}
			free.Call(uintptr(unsafe.Pointer(connection)))
		}
	}
	return result
}
