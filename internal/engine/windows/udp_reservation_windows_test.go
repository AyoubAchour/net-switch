//go:build windows

package winengine

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const dynamicUDPOutput = "\r\nProtocol udp Dynamic Port Range\r\n---------------------------------\r\nStart Port      : 49152\r\nNumber of Ports : 16384\r\n\r\n"

const excludedUDPOutput = "\r\nProtocol udp Port Exclusion Ranges\r\n\r\nStart Port    End Port\r\n----------    --------\r\n      5357        5357\r\n     50000       50059     *\r\n     50050       50100\r\n\r\n* - Administered port exclusions.\r\n\r\n"

func TestParseDynamicPortRange(t *testing.T) {
	value, err := parseDynamicPortRange(dynamicUDPOutput)
	if err != nil || value != (portRange{Start: 49152, End: 65535}) {
		t.Fatalf("got %+v, %v", value, err)
	}
	for _, output := range []string{"", "Start Port : 49152\r\n", "Start Port : 60000\r\nNumber of Ports : 6000\r\n", "Start Port : 0\r\nNumber of Ports : 10\r\n"} {
		if _, err := parseDynamicPortRange(output); err == nil {
			t.Errorf("accepted %q", output)
		}
	}
}

func TestParseExcludedPortRanges(t *testing.T) {
	ranges, err := parseExcludedPortRanges(excludedUDPOutput)
	want := []portRange{{Start: 5357, End: 5357}, {Start: 50000, End: 50059, Administered: true}, {Start: 50050, End: 50100}}
	if err != nil || !reflect.DeepEqual(ranges, want) {
		t.Fatalf("got %+v, %v", ranges, err)
	}
	// A real empty table is an empty list, not a missing one.
	empty := "\r\nProtocol udp Port Exclusion Ranges\r\n\r\nStart Port    End Port\r\n----------    --------\r\n\r\n* - Administered port exclusions.\r\n"
	if ranges, err := parseExcludedPortRanges(empty); err != nil || ranges == nil || len(ranges) != 0 {
		t.Fatalf("empty table: %+v, %v", ranges, err)
	}
	for _, output := range []string{"", "The requested operation requires elevation.\r\n", "----\r\n 10 9\r\n", "----\r\n 10 20 x\r\n", "----\r\n 10 70000\r\n"} {
		if _, err := parseExcludedPortRanges(output); err == nil {
			t.Errorf("accepted %q", output)
		}
	}
}

func TestUDPReservationAccountingIsPerFamilyAndDeduplicated(t *testing.T) {
	r := udpFamilyReservation{Family: "ipv4",
		DynamicCommand:  reservationCommandResult{Output: dynamicUDPOutput},
		ExcludedCommand: reservationCommandResult{Output: excludedUDPOutput}}
	// 5357 is excluded and used but outside the dynamic range; 50000 and
	// 50055 sit in the overlapping exclusions; 49152 and 60000 are only used.
	r.account([]uint16{5357, 49152, 50000, 50055, 60000}, true)
	if len(r.ParseErrors) != 0 {
		t.Fatal(r.ParseErrors)
	}
	got := map[string]int{"inUse": *r.InUsePorts, "dynamic": *r.DynamicPorts, "excluded": *r.ExcludedInDynamic,
		"used": *r.InUseInDynamic, "both": *r.InUseExcludedInDynamic, "available": *r.Available}
	want := map[string]int{"inUse": 5, "dynamic": 16384, "excluded": 101, "used": 4, "both": 2, "available": 16384 - 101 - 2}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestUDPReservationMissingInputsAreNotZero(t *testing.T) {
	r := udpFamilyReservation{Family: "ipv6",
		DynamicCommand:  reservationCommandResult{Output: dynamicUDPOutput},
		ExcludedCommand: reservationCommandResult{Error: "exit status 1", Output: "elevation required"}}
	r.account(nil, false)
	if r.DynamicPorts == nil || *r.DynamicPorts != 16384 {
		t.Fatalf("dynamic range lost: %+v", r)
	}
	if r.Available != nil || r.ExcludedInDynamic != nil || r.InUseInDynamic != nil || r.InUsePorts != nil || r.ExcludedRanges != nil {
		t.Fatalf("derived a count from missing input: %+v", r)
	}
	value, err := json.Marshal(r)
	if err != nil || strings.Contains(string(value), `"available"`) || !strings.Contains(string(value), "elevation required") {
		t.Fatalf("JSON %s, %v", value, err)
	}
	truncated := udpFamilyReservation{DynamicCommand: reservationCommandResult{Output: dynamicUDPOutput, Truncated: true}}
	truncated.account([]uint16{1}, true)
	if truncated.DynamicRange != nil || !reflect.DeepEqual(truncated.ParseErrors, []string{
		"dynamic: output truncated", "excluded: excluded port table header was not found",
	}) {
		t.Fatalf("truncated output parsed: %+v", truncated)
	}
}

// warmNetsh runs the probe's read-only commands once before the measured
// probe. A fresh hosted runner took over 15 s to start netsh for the first
// time (Windows x64 job 120046223484), which is the product's whole
// per-command deadline. The warm-up runs outside what the test measures and
// keeps that deadline, so a command killed on its cold start is retried: in
// the same job the next netsh start took 1.5 s and later ones 0 ms. A retry
// also keeps the warm-up faithful to how the probe runs the command.
func warmNetsh(t *testing.T) {
	t.Helper()
	for _, family := range []string{"ipv4", "ipv6"} {
		for _, args := range [][]string{
			{"interface", family, "show", "dynamicport", "udp"},
			{"interface", family, "show", "excludedportrange", "protocol=udp", "store=active"},
		} {
			for attempt := 1; ; attempt++ {
				result := runNetsh(context.Background(), args...)
				if result.Error == "" {
					break
				}
				if attempt == 3 {
					t.Fatalf("netsh warm-up %q failed after %s on attempt %d: %s", result.Command,
						time.Duration(result.Millis)*time.Millisecond, attempt, result.Error)
				}
				t.Logf("netsh warm-up %q attempt %d: %s after %s; retrying", result.Command, attempt,
					result.Error, time.Duration(result.Millis)*time.Millisecond)
			}
		}
	}
}

// The parsers above use recorded en-US text; this checks them against the
// hosted runner's real read-only netsh output, so a format drift fails here
// instead of turning the first real refusal's evidence into parse errors.
func TestUDPPortSpaceDiagnosisReadsHostedSettings(t *testing.T) {
	hosted(t)
	warmNetsh(t)
	space := diagnoseUDPPortSpace(context.Background())
	value, err := json.Marshal(space.Probe)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("WINDOWS UDP PORT SPACE %s", value)
	space.Probe.mu.Lock()
	defer space.Probe.mu.Unlock()
	if space.Probe.state != "complete" || len(space.Probe.families) != 2 {
		t.Fatalf("probe %s", value)
	}
	for _, family := range space.Probe.families {
		for _, command := range []struct {
			what   string
			result reservationCommandResult
		}{
			{"dynamic port range", family.DynamicCommand},
			{"excluded port ranges", family.ExcludedCommand},
		} {
			if command.result.Error != "" {
				t.Fatalf("%s %s: %q failed after %s: %s", family.Family, command.what,
					command.result.Command, time.Duration(command.result.Millis)*time.Millisecond, command.result.Error)
			}
		}
		if len(family.ParseErrors) != 0 || family.InUseError != "" ||
			family.DynamicRange == nil || family.ExcludedRanges == nil || family.Available == nil {
			t.Fatalf("%s port space was not fully derived: %+v", family.Family, family)
		}
		if *family.Available > *family.DynamicPorts || *family.ExcludedInDynamic+*family.InUseInDynamic-*family.InUseExcludedInDynamic+*family.Available != *family.DynamicPorts {
			t.Fatalf("%s accounting does not partition the dynamic range: %+v", family.Family, family)
		}
	}
}

func fakeNetsh(t *testing.T, calls *atomic.Int32) reservationCommand {
	return func(_ context.Context, args ...string) reservationCommandResult {
		calls.Add(1)
		joined := strings.Join(args, " ")
		if !strings.Contains(joined, " show ") {
			t.Errorf("not a read-only show command: %q", joined)
		}
		output := dynamicUDPOutput
		if strings.Contains(joined, "excludedportrange") {
			output = excludedUDPOutput
		}
		return reservationCommandResult{Command: "netsh " + joined, Output: output}
	}
}

func probeJSON(t *testing.T, probe *udpReservationProbe) map[string]any {
	t.Helper()
	value, err := json.Marshal(probe)
	if err != nil {
		t.Fatal(err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(value, &decoded); err != nil {
		t.Fatal(err)
	}
	return decoded
}

func TestUDPReservationProbeCompletesInBackground(t *testing.T) {
	var jobs reservationJobs
	var calls atomic.Int32
	release := make(chan struct{})
	run := fakeNetsh(t, &calls)
	blocked := func(ctx context.Context, args ...string) reservationCommandResult {
		<-release
		return run(ctx, args...)
	}
	space := &udpPortSpace{Probe: newUDPReservationProbe(), ports: [2][]uint16{{50000, 60000}, {50000}}}
	probe := space.Probe
	began := time.Now()
	jobs.start(space, blocked)
	if time.Since(began) > time.Second {
		t.Fatal("start waited for the commands")
	}
	if state := probeJSON(t, probe)["state"]; state != "pending" {
		t.Fatalf("state %v before commands finished", state)
	}
	close(release)
	jobs.wait.Wait() // Observe normal completion before testing Close's cancellation.
	jobs.close()
	decoded := probeJSON(t, probe)
	families, _ := decoded["families"].([]any)
	if decoded["state"] != "complete" || len(families) != 2 || calls.Load() != 4 {
		t.Fatalf("got %v after %d calls", decoded, calls.Load())
	}
	for index, want := range []float64{16384 - 101 - 1, 16384 - 101} {
		family := families[index].(map[string]any)
		if family["available"] != want {
			t.Fatalf("%v available %v, want %v", family["family"], family["available"], want)
		}
	}
}

func TestUDPReservationProbeStopsOnClose(t *testing.T) {
	var jobs reservationJobs
	entered := make(chan struct{}, 4)
	blocked := func(ctx context.Context, args ...string) reservationCommandResult {
		entered <- struct{}{}
		<-ctx.Done()
		return reservationCommandResult{Command: "netsh " + strings.Join(args, " "), Error: ctx.Err().Error()}
	}
	probe := newUDPReservationProbe()
	jobs.start(&udpPortSpace{Probe: probe, portsErr: errors.New("table unavailable")}, blocked)
	<-entered
	done := make(chan struct{})
	go func() {
		jobs.close()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("close did not join the probe")
	}
	decoded := probeJSON(t, probe)
	if decoded["state"] != "interrupted" {
		t.Fatalf("state %v", decoded["state"])
	}
	for _, family := range decoded["families"].([]any) {
		values := family.(map[string]any)
		if _, ok := values["available"]; ok || values["inUseError"] != "table unavailable" {
			t.Fatalf("interrupted family reported %v", values)
		}
	}

	// A probe requested after close never runs a command.
	var calls atomic.Int32
	late := newUDPReservationProbe()
	jobs.start(&udpPortSpace{Probe: late}, fakeNetsh(t, &calls))
	if state := probeJSON(t, late)["state"]; state != "cancelled" || calls.Load() != 0 {
		t.Fatalf("late probe %v after %d calls", state, calls.Load())
	}
}
