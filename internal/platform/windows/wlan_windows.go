package winplatform

import (
	"fmt"
	"runtime"
	"strings"
	"unicode/utf16"
	"unsafe"

	"golang.org/x/sys/windows"
)

var winrt = windows.NewLazySystemDLL("combase.dll")

// Interface IDs and vtable slots are the Windows SDK ABI, checked against
// microsoft/win32metadata's windows.networking.connectivity.h. This is our
// own binding, not a generated or adapted implementation.
var iidNetworkInformationStatics = windows.GUID{Data1: 0x5074f851, Data2: 0x950d, Data3: 0x4165, Data4: [8]byte{0x9c, 0x15, 0x36, 0x56, 0x19, 0x48, 0x1e, 0xea}}
var iidConnectionProfile2 = windows.GUID{Data1: 0xe2045145, Data2: 0x4c9f, Data3: 0x400c, Data4: [8]byte{0x91, 0x50, 0x7e, 0xc7, 0xd6, 0xe2, 0x88, 0x8a}}

func newHString(value string) (uintptr, error) {
	units := utf16.Encode([]rune(value))
	var data *uint16
	if len(units) > 0 {
		data = &units[0]
	}
	var handle uintptr
	hr, _, _ := winrt.NewProc("WindowsCreateString").Call(uintptr(unsafe.Pointer(data)), uintptr(len(units)), uintptr(unsafe.Pointer(&handle)))
	return handle, hresult(hr)
}

func deleteHString(handle uintptr) {
	winrt.NewProc("WindowsDeleteString").Call(handle)
}

func hStringValue(handle uintptr) string {
	var length uint32
	buffer, _, _ := winrt.NewProc("WindowsGetStringRawBuffer").Call(handle, uintptr(unsafe.Pointer(&length)))
	// HSTRING is length-delimited, can contain NUL, and uses NULL for empty.
	// Copy before WindowsDeleteString; do not trim meaningful SSID spaces.
	// The return value is a native pointer, not an address into the Go heap.
	data := *(**uint16)(unsafe.Pointer(&buffer))
	return string(utf16.Decode(unsafe.Slice(data, length)))
}

// readSSIDs uses only Microsoft's location-free SSID API. In particular, do
// not fall back to Native Wi-Fi, GetLanIdentifiers, or profile display names.
// Unsupported service contexts and failures leave the optional label null.
// https://learn.microsoft.com/windows/win32/nativewifi/wi-fi-access-location-changes
func readSSIDs() (map[string]string, error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	hr, _, _ := winrt.NewProc("RoInitialize").Call(1) // RO_INIT_MULTITHREADED
	if err := hresult(hr); err != nil {
		return nil, fmt.Errorf("initialize WinRT: %w", err)
	}
	defer winrt.NewProc("RoUninitialize").Call() // Also balances S_FALSE.
	name, err := newHString("Windows.Networking.Connectivity.NetworkInformation")
	if err != nil {
		return nil, err
	}
	defer deleteHString(name)
	var factory *comObject
	hr, _, _ = winrt.NewProc("RoGetActivationFactory").Call(name, uintptr(unsafe.Pointer(&iidNetworkInformationStatics)), uintptr(unsafe.Pointer(&factory)))
	if err := hresult(hr); err != nil {
		return nil, fmt.Errorf("activate NetworkInformation: %w", err)
	}
	defer factory.release()
	var profiles *comObject
	if _, err := factory.invokeSlot(6, uintptr(unsafe.Pointer(&profiles))); err != nil { // GetConnectionProfiles
		return nil, fmt.Errorf("enumerate connection profiles: %w", err)
	}
	if profiles == nil {
		return nil, nil
	}
	defer profiles.release()
	var count uint32
	if _, err := profiles.invokeSlot(7, uintptr(unsafe.Pointer(&count))); err != nil { // IVectorView.Size
		return nil, err
	}
	result := map[string]string{}
	var firstError error
	for i := uint32(0); i < count; i++ {
		var profile *comObject
		_, err := profiles.invokeSlot(6, uintptr(i), uintptr(unsafe.Pointer(&profile))) // IVectorView.GetAt
		if err == nil && profile != nil {
			var id windows.GUID
			var ssid string
			id, ssid, err = connectedSSID(profile)
			profile.release()
			if err == nil && id != (windows.GUID{}) && ssid != "" {
				result[strings.ToLower(id.String())] = ssid
			}
		}
		if err != nil && firstError == nil {
			firstError = fmt.Errorf("read connection profile %d: %w", i, err)
		}
	}
	return result, firstError
}

func connectedSSID(profile *comObject) (windows.GUID, string, error) {
	var id windows.GUID
	var level uint32
	if _, err := profile.invokeSlot(7, uintptr(unsafe.Pointer(&level))); err != nil { // GetNetworkConnectivityLevel
		return id, "", err
	}
	if level == 0 { // Known profiles include disconnected networks.
		return id, "", nil
	}
	var details *comObject
	if _, err := profile.invokeSlot(0, uintptr(unsafe.Pointer(&iidConnectionProfile2)), uintptr(unsafe.Pointer(&details))); err != nil {
		return id, "", err
	}
	defer details.release()
	var isWlan uint8 // WinRT boolean is one byte, not a Win32 BOOL.
	if _, err := details.invokeSlot(7, uintptr(unsafe.Pointer(&isWlan))); err != nil {
		return id, "", err
	}
	if isWlan == 0 {
		return id, "", nil
	}
	var adapter *comObject
	if _, err := profile.invokeSlot(11, uintptr(unsafe.Pointer(&adapter))); err != nil { // NetworkAdapter
		return id, "", err
	}
	if adapter == nil {
		return id, "", nil
	}
	defer adapter.release()
	if _, err := adapter.invokeSlot(10, uintptr(unsafe.Pointer(&id))); err != nil { // NetworkAdapterId
		return id, "", err
	}
	var wlanDetails *comObject
	if _, err := details.invokeSlot(9, uintptr(unsafe.Pointer(&wlanDetails))); err != nil { // WlanConnectionProfileDetails
		return id, "", err
	}
	if wlanDetails == nil {
		return id, "", nil
	}
	defer wlanDetails.release()
	var ssid uintptr
	if _, err := wlanDetails.invokeSlot(6, uintptr(unsafe.Pointer(&ssid))); err != nil { // GetConnectedSsid
		return id, "", err
	}
	defer deleteHString(ssid)
	return id, hStringValue(ssid), nil
}
