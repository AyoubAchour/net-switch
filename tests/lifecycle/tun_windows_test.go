package lifecycle_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/AyoubAchour/net-switch/internal/lifecycle"
)

func powershell(t *testing.T, script string, env ...string) []byte {
	t.Helper()
	cmd := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script)
	cmd.Env = append(os.Environ(), env...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatal("fixture PowerShell", err, string(out))
	}
	return out
}
func prepareTUN(t *testing.T, dir, data string) tunFixture {
	t.Helper()
	nic, address := primaryInterface(t)
	iface, err := net.InterfaceByName(nic)
	if err != nil {
		t.Fatal(err)
	}
	echo := echoServer(t, address)
	_, port, _ := net.SplitHostPort(echo)
	statePath := filepath.Join(data, "testisp-ready.json")
	token := strings.Repeat("fixture-", 8)
	cmd := exec.Command(filepath.Join(dir, "testisp.exe"), "serve", "--uplink-index", strconv.Itoa(iface.Index), "--uplink-ip", address, "--state", statePath)
	cmd.Env = append(os.Environ(), "TESTISP_TOKEN="+token)
	var logs bytes.Buffer
	cmd.Stderr = &logs
	cmd.Stdout = &logs
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait(); t.Log(logs.String()) })
	var state struct {
		Index   int    `json:"index"`
		Control string `json:"control"`
	}
	wait(t, "TestISP ready", 30*time.Second, func() bool { return lifecycle.Read(statePath, &state) == nil && state.Index > 0 })
	script, _ := filepath.Abs("../windows/testisp/network.ps1")
	powershell(t, fmt.Sprintf("& '%s' -Action configure", strings.ReplaceAll(script, "'", "''")), "TESTISP_INDEX="+strconv.Itoa(state.Index))
	// Direct traffic uses this fixture's default route. NetSwitch's TUN
	// routes must capture it while on, and release it after failure.
	powershell(t, fmt.Sprintf("Get-NetRoute -InterfaceIndex %d -DestinationPrefix '0.0.0.0/0' | Set-NetRoute -RouteMetric 1; Set-NetIPInterface -InterfaceIndex %d -AddressFamily IPv4 -InterfaceMetric 1", state.Index, state.Index))
	request, _ := http.NewRequest("POST", state.Control+"/targets", strings.NewReader(`{"ports":[`+port+`]}`))
	request.Header.Set("Authorization", "Bearer "+token)
	response, err := (&http.Client{Timeout: 5 * time.Second}).Do(request)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != 200 {
		t.Fatal("TestISP target mapping", response.StatusCode)
	}
	return tunFixture{
		line: "TestISP", target: "198.19.128.2:" + port, dial: (&net.Dialer{Timeout: 5 * time.Second}).DialContext, exchange: checkEcho,
		installed: func(t *testing.T) {
			out := powershell(t, "$a=Get-NetAdapter -Name NetSwitch -ErrorAction Stop; $routes=@(Get-NetRoute -InterfaceIndex $a.ifIndex); if ($routes.Count -lt 1) {throw 'TUN has no routes'}; [pscustomobject]@{index=$a.ifIndex;routes=$routes.Count}|ConvertTo-Json -Compress")
			var evidence map[string]any
			if json.Unmarshal(out, &evidence) != nil {
				t.Fatal(string(out))
			}
			t.Log("TUN adapter and routes", evidence)
		},
		clean: func(t *testing.T) {
			powershell(t, "$a=@(Get-NetAdapter -IncludeHidden | Where-Object Name -eq NetSwitch); $r=@(Get-NetRoute | Where-Object InterfaceAlias -eq NetSwitch); $f=@(Get-NetFirewallRule | Where-Object DisplayName -like '*NetSwitch*'); if ($a.Count -or $r.Count -or $f.Count) {throw ('TUN leftovers: adapters={0} routes={1} rules={2}' -f $a.Count,$r.Count,$f.Count)}")
		},
	}
}
