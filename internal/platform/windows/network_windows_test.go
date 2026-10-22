package winplatform

import (
	"errors"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

func TestNetworkWindowsLayouts(t *testing.T) {
	// Windows x64 and ARM64 both align pointers and uint64 fields to 8 bytes.
	// These are the SDK offsets used by iphlpapi.
	checks := []struct{ got, want uintptr }{
		{unsafe.Sizeof(uintptr(0)), 8},
		{unsafe.Alignof(windows.MibIfRow2{}), 8},
		{unsafe.Offsetof(windows.MibIfTable2{}.Table), 8},
		{unsafe.Offsetof(windows.IpAdapterAddresses{}.Next), 8},
		{unsafe.Sizeof(windows.MibIpForwardRow2{}), 104},
		{unsafe.Offsetof(windows.MibIpForwardTable2{}.Table), 8},
		{unsafe.Offsetof(windows.MibIpInterfaceRow{}.Metric), 148},
	}
	for _, c := range checks {
		if c.got != c.want {
			t.Errorf("Windows layout: got %d want %d", c.got, c.want)
		}
	}
}

func TestNetworkPresentation(t *testing.T) {
	for speed, want := range map[uint64]string{0: "0 bps", 100_000_000: "100 Mbps", 866_700_000: "866.7 Mbps", 10_000_000_000: "10 Gbps", 1_250_000: "1.2 Mbps", 1_350_000: "1.4 Mbps"} {
		if got := linkSpeed(speed); got != want {
			t.Errorf("%d: %s, want %s", speed, got, want)
		}
	}
	if mediaType(9) != "Native 802.11" || mediaType(14) != "802.3" || mediaType(0) != "Unspecified" {
		t.Fatal("physical media names changed")
	}
	for _, c := range []struct {
		admin, oper uint32
		flags       uint8
		want        string
	}{
		{1, 1, 0, "Up"}, {2, 2, 16, "Disabled"}, {1, 2, 16, "Disconnected"}, {1, 6, 0, "Not Present"},
		{1, 7, 0, "Lower Layer Down"}, {1, 3, 0, "Testing"}, {1, 2, 88, "Not Authenticated, Disconnected, Low Power State"},
	} {
		row := windows.MibIfRow2{AdminStatus: c.admin, OperStatus: c.oper, InterfaceAndOperStatusFlags: c.flags}
		if got := adapterStatus(&row); got != c.want {
			t.Errorf("status: %s, want %s", got, c.want)
		}
	}
}

func TestMissingIPInterfaceDoesNotDiscardSnapshot(t *testing.T) {
	for _, gone := range []error{windows.ERROR_NOT_FOUND, windows.ERROR_FILE_NOT_FOUND} {
		rows := []windows.MibIfRow2{{InterfaceIndex: 1, Type: 6}, {InterfaceIndex: 2, Type: 6}}
		addresses := map[uint32][]string{1: {"192.168.1.2"}, 2: {"192.168.2.2"}}
		routes := []windows.MibIpForwardRow2{{InterfaceIndex: 1}, {InterfaceIndex: 2}}
		line, err := assembleNetwork(networkLine{}, rows, addresses, routes, nil, nil, func(row *windows.MibIpInterfaceRow) error {
			if row.InterfaceIndex == 1 {
				return gone
			}
			row.Metric = 25
			return nil
		})
		wantAdapters := 1
		if errors.Is(gone, windows.ERROR_NOT_FOUND) {
			wantAdapters = 2 // Missing IPv4 does not mean the device is gone.
		}
		if err != nil || len(line.Adapters) != wantAdapters || line.Adapters[len(line.Adapters)-1].Index != 2 || len(line.DefaultRoutes) != 1 || line.DefaultRoutes[0].InterfaceAddress != "192.168.2.2" {
			t.Fatalf("missing IP interface (%v): %+v, %v", gone, line, err)
		}
	}
	_, err := assembleNetwork(networkLine{}, []windows.MibIfRow2{{Type: 6}}, nil, nil, nil, nil, func(*windows.MibIpInterfaceRow) error {
		return windows.ERROR_ACCESS_DENIED
	})
	if !errors.Is(err, windows.ERROR_ACCESS_DENIED) {
		t.Fatalf("unexpected errors must still reject the partial scan: %v", err)
	}
}

func TestVisibleAdapterWithoutIPv4(t *testing.T) {
	// Runner evidence: the Mellanox VF has flags 0x05 and is Up, visible,
	// and present, but GetIpInterfaceEntry(AF_INET) returns ERROR_NOT_FOUND.
	row := windows.MibIfRow2{InterfaceIndex: 3, Type: 6, OperStatus: 1, InterfaceAndOperStatusFlags: 0x05}
	copy(row.Alias[:], windows.StringToUTF16("Ethernet 4"))
	copy(row.Description[:], windows.StringToUTF16("Mellanox ConnectX-4 Lx Virtual Ethernet Adapter"))
	row.InterfaceGuid, _ = windows.GUIDFromString("{FDA85F00-AD70-425D-8F0C-D4E774F25F27}")
	line, err := assembleNetwork(networkLine{}, []windows.MibIfRow2{row}, nil, nil, nil, nil, func(ipif *windows.MibIpInterfaceRow) error {
		if ipif.Family != windows.AF_INET || ipif.InterfaceIndex != 3 {
			t.Fatalf("unexpected IPv4 lookup: %+v", ipif)
		}
		return windows.ERROR_NOT_FOUND
	})
	if err != nil || len(line.Adapters) != 1 {
		t.Fatalf("visible adapter without IPv4 was lost: %+v, %v", line, err)
	}
	adapter := line.Adapters[0]
	if adapter.Alias != "Ethernet 4" || adapter.GUID != row.InterfaceGuid.String() || adapter.Status != "Up" || adapter.Virtual {
		t.Fatalf("device identity changed: %+v", adapter)
	}
	if adapter.Gateway != nil || adapter.RouteMetric != nil || adapter.Metric != nil || adapter.AutomaticMetric != nil || adapter.IPv4 != nil || adapter.IPv4s == nil || len(adapter.IPv4s) != 0 || len(line.DefaultRoutes) != 0 {
		t.Fatalf("adapter without IPv4 must have null IPv4 fields and an empty address list: %+v", line)
	}
}

func TestNetworkAddressErrorsAreNotEmptySnapshots(t *testing.T) {
	for _, failure := range []error{windows.ERROR_NO_DATA, windows.ERROR_INVALID_PARAMETER} {
		query := func(uint32, uint32, uintptr, *windows.IpAdapterAddresses, *uint32) error { return failure }
		if _, err := queryAdapterAddresses(true, query); !errors.Is(err, failure) {
			t.Fatalf("network mode hid %v: %v", failure, err)
		}
		if first, err := queryAdapterAddresses(false, query); first != nil || err != nil {
			t.Fatalf("meters compatibility changed: %v, %v", first, err)
		}
	}
}

type stringPolicy struct {
	value string
	kind  uint32
}

func (key stringPolicy) GetIntegerValue(string) (uint64, uint32, error) {
	return 0, key.kind, registry.ErrUnexpectedType
}

func (key stringPolicy) GetStringValue(string) (string, uint32, error) {
	return key.value, key.kind, nil
}

func TestPolicyAcceptsNumericREGSZ(t *testing.T) {
	for _, value := range []string{"3", " 3 ", "+3"} {
		got, err := policyValue(stringPolicy{value, registry.SZ})
		if err != nil || got != int32(3) {
			t.Fatalf("REG_SZ %q: %v, %v", value, got, err)
		}
	}
	for _, key := range []stringPolicy{{"invalid", registry.SZ}, {"3oops", registry.SZ}, {"2147483648", registry.SZ}, {"3", registry.EXPAND_SZ}} {
		if _, err := policyValue(key); err == nil {
			t.Fatalf("invalid policy accepted: %+v", key)
		}
	}
}
