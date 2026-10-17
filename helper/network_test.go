package main

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
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
		{"guard", "--parent", "123", "--child", "456", "--child-path", `C:\engine.exe`},
	} {
		if _, err := parseArgs(args); err != nil {
			t.Errorf("%v: %v", args, err)
		}
	}
	for _, args := range [][]string{
		{"guard"}, {"guard", "--parent", "1", "--child", "1", "--child-path", "x"},
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

func TestGuardIdentity(t *testing.T) {
	for _, c := range []struct {
		actual, expected string
		parent, child    uint64
		want             bool
	}{
		{`C:\engine.exe`, `c:\ENGINE.exe`, 10, 11, true},
		{`C:\other.exe`, `c:\engine.exe`, 10, 11, false},
		{`C:\engine.exe`, `c:\engine.exe`, 10, 9, false},
		{`C:\engine.exe`, `c:\engine.exe`, 10, 10, false},
		{"", "", 10, 11, false},
	} {
		if got := guardMatches(c.actual, c.expected, c.parent, c.child); got != c.want {
			t.Errorf("%+v: %v", c, got)
		}
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
