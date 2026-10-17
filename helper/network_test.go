package main

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

func TestNetworkWindowsLayouts(t *testing.T) {
	checks := []struct{ got, want uintptr }{
		{unsafe.Sizeof(windows.MibIpForwardRow2{}), 104},
		{unsafe.Offsetof(windows.MibIpForwardTable2{}.Table), 8},
		{unsafe.Offsetof(windows.MibIpInterfaceRow{}.Metric), 148},
		{unsafe.Offsetof(wlanInterfaceList{}.Interfaces), 8},
		{unsafe.Sizeof(wlanInterface{}), 532},
		{unsafe.Offsetof(wlanConnection{}.SSIDLength), 520},
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

func TestNewArguments(t *testing.T) {
	for _, args := range [][]string{
		{"network", "--once"}, {"network", "--parent", "123"},
		{"probe", "--interface-index", "3", "--targets", "1.1.1.1:443,8.8.8.8:443"},
		{"policy"},
	} {
		if _, err := parseArgs(args); err != nil {
			t.Errorf("%v: %v", args, err)
		}
	}
	for _, args := range [][]string{
		{"probe", "--interface-index", "0", "--targets", "1.1.1.1:443"},
		{"probe", "--interface-index", "1", "--targets", "example.com:443"},
		{"probe", "--interface-index", "1", "--targets", "[::1]:443"},
		{"probe", "--interface-index", "1", "--targets", "1.1.1.1:0"},
		{"probe", "--interface-index", "1", "--targets", "1.1.1.1:443", "--timeout-ms", "0"},
	} {
		if _, err := parseArgs(args); err == nil {
			t.Errorf("accepted %v", args)
		}
	}
}

func TestFirstSuccessfulProbeCancelsTheOther(t *testing.T) {
	cancelled := make(chan struct{})
	result := raceProbes(context.Background(), []string{"slow", "fast"}, func(ctx context.Context, target string) error {
		if target == "fast" {
			return nil
		}
		<-ctx.Done()
		close(cancelled)
		return ctx.Err()
	})
	if !result.OK || result.Target != "fast" || result.MS < 1 {
		t.Fatalf("%+v", result)
	}
	select {
	case <-cancelled:
	case <-time.After(time.Second):
		t.Fatal("the losing probe wasn't cancelled")
	}
	result = raceProbes(context.Background(), []string{"a", "b"}, func(context.Context, string) error { return errors.New("refused") })
	if result.OK || !strings.Contains(result.Error, "a: refused") || !strings.Contains(result.Error, "b: refused") {
		t.Fatalf("%+v", result)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	result = raceProbes(ctx, []string{"a"}, func(ctx context.Context, _ string) error { <-ctx.Done(); return ctx.Err() })
	if result.OK || result.Error == "" {
		t.Fatalf("%+v", result)
	}
}

func TestNetworkCoalescesBurstsAndStillRefreshesWhenQuiet(t *testing.T) {
	changed := make(chan struct{}, 100)
	emitted := make(chan time.Time, 10)
	done := make(chan error, 1)
	stop := errors.New("reader closed")
	go func() {
		calls := 0
		done <- streamNetwork(changed, func() error {
			calls++
			emitted <- time.Now()
			if calls == 3 {
				return stop
			}
			return nil
		}, 150*time.Millisecond, 30*time.Millisecond)
	}()
	start := <-emitted
	for range 100 {
		changed <- struct{}{}
	}
	burst := <-emitted
	if burst.Sub(start) < 20*time.Millisecond {
		t.Fatal("burst wasn't coalesced")
	}
	refresh := <-emitted
	if refresh.Sub(start) < 100*time.Millisecond {
		t.Fatal("burst generated extra snapshots")
	}
	if err := <-done; !errors.Is(err, stop) {
		t.Fatalf("write failure wasn't propagated: %v", err)
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

func TestNetworkRetriesReadFailureWithoutExiting(t *testing.T) {
	stop := errors.New("output closed")
	calls := 0
	started := time.Now()
	err := streamNetwork(make(chan struct{}), func() error {
		calls++
		if calls < 3 {
			return &networkReadError{windows.ERROR_ACCESS_DENIED}
		}
		return stop
	}, time.Hour, time.Millisecond)
	if !errors.Is(err, stop) || calls != 3 || time.Since(started) < 1500*time.Millisecond {
		t.Fatalf("calls=%d elapsed=%s err=%v", calls, time.Since(started), err)
	}
}
