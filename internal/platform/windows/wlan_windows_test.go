package winplatform

import (
	"encoding/json"
	"errors"
	"runtime"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

func TestSSIDHStringParsing(t *testing.T) {
	for _, want := range []string{"", "Home", "  Home  ", "réseau 日本 📶", "one\x00two"} {
		handle, err := newHString(want)
		if err != nil {
			t.Fatal(err)
		}
		got := hStringValue(handle)
		deleteHString(handle)
		if got != want {
			t.Fatalf("HSTRING %q: got %q", want, got)
		}
	}
	if got := hStringValue(0); got != "" {
		t.Fatalf("NULL HSTRING: %q", got)
	}
}

// These callbacks exercise our actual ABI binding and every early return
// without reading this PC's network. Acquired COM references must balance.
func TestSSIDProfileLifetime(t *testing.T) {
	for _, scenario := range []string{"ok", "disconnected", "ethernet", "no-adapter", "no-details", "empty", "level-error", "query-error", "kind-error", "adapter-error", "id-error", "details-error", "ssid-error"} {
		t.Run(scenario, func(t *testing.T) {
			wantID := windows.GUID{Data1: 0xaabbccdd, Data2: 0x1122, Data3: 0x3344}
			refs := map[string]int{}
			object := func(name string) *comObject {
				o := &comObject{vt: new([32]uintptr)}
				o.vt[2] = windows.NewCallback(func(uintptr) uintptr { refs[name]--; return 0 })
				return o
			}
			profile, details, adapter, wlanDetails := object("profile"), object("details"), object("adapter"), object("wlan")
			denied := uintptr(0x80070005)
			profile.vt[7] = windows.NewCallback(func(_ uintptr, out *uint32) uintptr {
				if scenario == "level-error" {
					return denied
				}
				if scenario != "disconnected" {
					*out = 1
				}
				return 0
			})
			profile.vt[0] = windows.NewCallback(func(_ uintptr, iid *windows.GUID, out **comObject) uintptr {
				if *iid != iidConnectionProfile2 {
					t.Error("wrong profile IID")
				}
				if scenario == "query-error" {
					return denied
				}
				*out = details
				refs["details"]++
				return 0
			})
			details.vt[7] = windows.NewCallback(func(_ uintptr, out *uint8) uintptr {
				if scenario == "kind-error" {
					return denied
				}
				if scenario != "ethernet" {
					*out = 1
				}
				return 0
			})
			profile.vt[11] = windows.NewCallback(func(_ uintptr, out **comObject) uintptr {
				if scenario == "adapter-error" {
					return denied
				}
				if scenario != "no-adapter" {
					*out = adapter
					refs["adapter"]++
				}
				return 0
			})
			adapter.vt[10] = windows.NewCallback(func(_ uintptr, out *windows.GUID) uintptr {
				if scenario == "id-error" {
					return denied
				}
				*out = wantID
				return 0
			})
			details.vt[9] = windows.NewCallback(func(_ uintptr, out **comObject) uintptr {
				if scenario == "details-error" {
					return denied
				}
				if scenario != "no-details" {
					*out = wlanDetails
					refs["wlan"]++
				}
				return 0
			})
			wlanDetails.vt[6] = windows.NewCallback(func(_ uintptr, out *uintptr) uintptr {
				if scenario == "ssid-error" {
					return denied
				}
				name := "  réseau 📶  "
				if scenario == "empty" {
					name = ""
				}
				handle, err := newHString(name)
				if err != nil {
					t.Error(err)
					return denied
				}
				*out = handle
				return 0
			})
			id, ssid, err := connectedSSID(profile)
			if strings.HasSuffix(scenario, "-error") {
				var failure *comError
				if !errors.As(err, &failure) || failure.Code != uint32(denied) {
					t.Fatalf("lost HRESULT: %v", err)
				}
			} else if err != nil {
				t.Fatal(err)
			}
			if scenario == "ok" {
				if id != wantID || ssid != "  réseau 📶  " {
					t.Fatalf("wrong adapter/name: %v, %q", id, ssid)
				}
			} else if ssid != "" {
				t.Fatalf("unavailable SSID must be empty: %q", ssid)
			}
			for name, count := range refs {
				if count != 0 {
					t.Errorf("%s references left: %d", name, count)
				}
			}
			runtime.KeepAlive([]*comObject{profile, details, adapter, wlanDetails})
		})
	}
}

func TestSSIDAdapterJSONNull(t *testing.T) {
	id := windows.GUID{Data1: 0xaabbccdd, Data2: 0x1122, Data3: 0x3344}
	for _, names := range []map[string]string{nil, {}, {strings.ToLower(id.String()): "réseau"}} {
		line, err := assembleNetwork(networkLine{}, []windows.MibIfRow2{{InterfaceGuid: id, Type: 71}}, nil, nil, names, nil, func(*windows.MibIpInterfaceRow) error { return nil })
		if err != nil {
			t.Fatal(err)
		}
		data, err := json.Marshal(line.Adapters[0])
		if err != nil {
			t.Fatal(err)
		}
		want := `"ssid":null`
		if len(names) != 0 {
			want = `"ssid":"réseau"`
		}
		if !strings.Contains(string(data), want) {
			t.Fatalf("contract changed: %s", data)
		}
	}
}
