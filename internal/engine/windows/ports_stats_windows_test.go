//go:build windows && (acceptance || netswitch_handlecheck)

package winengine

import (
	"context"
	"encoding/json"
	"os/exec"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestPortConfigurationMatchesNativeProvider(t *testing.T) {
	hosted(t)
	requireProcessDiagnostics(t)
	// The restricted worker keeps its own 30 s bound. The PowerShell oracle
	// below gets a separate budget: one CIM call alone takes 20-30 s on the
	// ARM64 runner, and sharing the worker's budget failed run 39559172829
	// with the worker's answer already in hand.
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	// Exercise the trace build's diagnostic entry point, including its real
	// restricted worker. It must read WMI with its actual Medium token.
	began := time.Now()
	actual, err := readPortConfiguration(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("restricted worker answered in %s (bound 30s)", time.Since(began).Round(time.Millisecond))
	var oracle []portTemplate
	// PowerShell is confined to the hosted oracle; production uses COM.
	oracleCtx, oracleCancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer oracleCancel()
	began = time.Now()
	b, err := exec.CommandContext(oracleCtx, "powershell.exe", "-NoProfile", "-NonInteractive", "-Command",
		"Get-NetTCPSetting | Select-Object SettingName,DynamicPortRangeStartPort,DynamicPortRangeNumberOfPorts,AutoReusePortRangeStartPort,AutoReusePortRangeNumberOfPorts | ConvertTo-Json -Compress").Output()
	if err != nil {
		t.Fatalf("PowerShell oracle after %s: %v", time.Since(began).Round(time.Millisecond), err)
	}
	t.Logf("PowerShell oracle answered in %s", time.Since(began).Round(time.Millisecond))
	if err := json.Unmarshal(b, &oracle); err != nil {
		t.Fatal(err)
	}
	compare := func(a, b portTemplate) int { return strings.Compare(a.SettingName, b.SettingName) }
	slices.SortFunc(actual, compare)
	slices.SortFunc(oracle, compare)
	if len(actual) == 0 || !reflect.DeepEqual(actual, oracle) {
		t.Fatalf("restricted native provider=%+v oracle=%s", actual, b)
	}
	t.Logf("restricted native TCP settings match every oracle property including inherited nulls: %s", b)
}
