//go:build windows && (acceptance || netswitch_handlecheck)

package winengine

import (
	"context"
	"encoding/json"
	"testing"
	"time"
)

// warmNetsh runs the probe's read-only commands once before the measured
// probe. A fresh hosted runner took over 15 s to start netsh for the first
// time (Windows x64 job 120046223484), which is the diagnostic's whole
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

// The parser unit tests use recorded en-US text; this checks them against the
// hosted runner's real read-only netsh output, so a format drift fails here
// instead of turning the first real refusal's evidence into parse errors.
func TestUDPPortSpaceDiagnosisReadsHostedSettings(t *testing.T) {
	hosted(t)
	requireProcessDiagnostics(t)
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
