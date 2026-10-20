//go:build windows

package winengine

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/AyoubAchour/net-switch/internal/platform/worker"
)

func TestPortConfigurationMatchesNativeProvider(t *testing.T) {
	hosted(t)
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	// This is the production restricted worker, not a direct call as the
	// elevated test runner. It must read WMI with its actual Medium token.
	value, err := (worker.Supervisor{Executable: executable}).Once(ctx, "tcp-port-configuration", nil)
	if err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	var actual, oracle []portTemplate
	if err := json.Unmarshal(b, &actual); err != nil {
		t.Fatal(err)
	}
	// PowerShell is confined to the hosted oracle; production uses COM.
	b, err = exec.CommandContext(ctx, "powershell.exe", "-NoProfile", "-NonInteractive", "-Command",
		"Get-NetTCPSetting | Select-Object SettingName,DynamicPortRangeStartPort,DynamicPortRangeNumberOfPorts,AutoReusePortRangeStartPort,AutoReusePortRangeNumberOfPorts | ConvertTo-Json -Compress").Output()
	if err != nil {
		t.Fatal(err)
	}
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
