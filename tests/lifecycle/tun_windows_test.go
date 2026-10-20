package lifecycle_test

import (
	"bytes"
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
	"unsafe"

	"github.com/AyoubAchour/net-switch/internal/lifecycle"
	"golang.org/x/sys/windows"
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
	var tunIndex uint32
	return tunFixture{
		line: "TestISP", target: "198.19.128.2:" + port, dial: (&net.Dialer{Timeout: 5 * time.Second}).DialContext, exchange: checkEcho,
		installed: func(t *testing.T) {
			index, routes, err := nativeTUNState(0)
			if err != nil || index == 0 || routes == 0 {
				t.Fatal("native TUN precondition", index, routes, err)
			}
			tunIndex = index
			t.Logf("native TUN precondition: interface=%d routes=%d", index, routes)
		},
		clean: func(t *testing.T) {
			wait(t, "native adapter and routes gone", 10*time.Second, func() bool {
				index, routes, err := nativeTUNState(tunIndex)
				if err != nil {
					t.Fatal(err)
				}
				return index == 0 && routes == 0
			})
		},
	}
}

func nativeTUNState(previous uint32) (uint32, int, error) {
	var interfaces *windows.MibIfTable2
	if err := windows.GetIfTable2Ex(windows.MibIfTableNormal, &interfaces); err != nil {
		return 0, 0, err
	}
	defer windows.FreeMibTable(unsafe.Pointer(interfaces))
	var index uint32
	for _, row := range unsafe.Slice(&interfaces.Table[0], interfaces.NumEntries) {
		if windows.UTF16ToString(row.Alias[:]) == "NetSwitch" {
			index = row.InterfaceIndex
			previous = index
		}
	}
	var routes *windows.MibIpForwardTable2
	if err := windows.GetIpForwardTable2(windows.AF_UNSPEC, &routes); err != nil {
		return 0, 0, err
	}
	defer windows.FreeMibTable(unsafe.Pointer(routes))
	count := 0
	for _, row := range routes.Rows() {
		if previous != 0 && row.InterfaceIndex == previous {
			count++
		}
	}
	return index, count, nil
}
