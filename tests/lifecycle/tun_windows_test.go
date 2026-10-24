package lifecycle_test

import (
	"bytes"
	"errors"
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

	winengine "github.com/AyoubAchour/net-switch/internal/engine/windows"
	"github.com/AyoubAchour/net-switch/internal/lifecycle"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
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
	var state struct {
		Index   int    `json:"index"`
		Control string `json:"control"`
		GUID    string `json:"guid"`
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		t.Log(logs.String())
		// Wintun removes the adapter asynchronously after the process dies.
		// The next TestISP refuses a present adapter under the engine's
		// absence rule, so wait here until that rule says it is gone.
		if state.GUID == "" {
			return
		}
		deadline := time.Now().Add(30 * time.Second)
		for {
			present, reason, err := winengine.LeftoverAdapterPresent(state.GUID, "TestISP")
			if err == nil && !present {
				t.Logf("TestISP adapter gone: %s", reason)
				return
			}
			if time.Now().After(deadline) {
				t.Errorf("TestISP adapter still present 30 s after its process exited: %s (error=%v)", reason, err)
				return
			}
			time.Sleep(250 * time.Millisecond)
		}
	})
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
		probe: func(t *testing.T, data string) nativeProbeFixture {
			proof := windowsNativeProbe(t, data, address)
			_, probePort, _ := net.SplitHostPort(proof.target)
			r, _ := http.NewRequest("POST", state.Control+"/targets", strings.NewReader(fmt.Sprintf(`{"ports":[%s,%s]}`, port, probePort)))
			r.Header.Set("Authorization", "Bearer "+token)
			response, err := (&http.Client{Timeout: 5 * time.Second}).Do(r)
			if err != nil {
				t.Fatal(err)
			}
			response.Body.Close()
			if response.StatusCode != 200 {
				t.Fatal("probe target mapping", response.StatusCode)
			}
			return proof
		},
		installed: func(t *testing.T) {
			index, routes, err := nativeTUNState(0)
			if err != nil || index == 0 || routes == 0 {
				t.Fatal("native TUN precondition", index, routes, err)
			}
			tunIndex = index
			t.Logf("native TUN precondition: interface=%d routes=%d", index, routes)
		},
		clean: func(t *testing.T) {
			var lastIndex uint32
			var lastRoutes int
			defer func() {
				t.Logf("native cleanup inventory: index=%d routes=%d original_index=%d", lastIndex, lastRoutes, tunIndex)
				logNativeTUNInventory(t, tunIndex)
			}()
			wait(t, "native adapter and routes gone", 10*time.Second, func() bool {
				index, routes, err := nativeTUNState(tunIndex)
				lastIndex, lastRoutes = index, routes
				if err != nil {
					t.Fatal(err)
				}
				return index == 0 && routes == 0
			})
		},
		audit: func(t *testing.T) {
			// Preserve the broader firewall assertion outside the native timed
			// interval. ARM64 CIM inventory latency is not cleanup latency.
			powershell(t, "$a=@(Get-NetAdapter -IncludeHidden | Where-Object Name -eq NetSwitch); $r=@(Get-NetRoute | Where-Object InterfaceAlias -eq NetSwitch); $f=@(Get-NetFirewallRule | Where-Object DisplayName -like '*NetSwitch*'); if ($a.Count -or $r.Count -or $f.Count) {throw ('TUN leftovers: adapters={0} routes={1} rules={2}' -f $a.Count,$r.Count,$f.Count)}")
		},
	}
}

func logNativeTUNInventory(t *testing.T, previous uint32) {
	var table *windows.MibIfTable2
	if err := windows.GetIfTable2Ex(windows.MibIfTableNormal, &table); err != nil {
		t.Log("native interface inventory", err)
		return
	}
	defer windows.FreeMibTable(unsafe.Pointer(table))
	for _, row := range unsafe.Slice(&table.Table[0], table.NumEntries) {
		if row.InterfaceIndex == previous || windows.UTF16ToString(row.Alias[:]) == "NetSwitch" {
			t.Logf("native interface: index=%d alias=%q status=%d flags=%#x guid=%s", row.InterfaceIndex, windows.UTF16ToString(row.Alias[:]), row.OperStatus, row.InterfaceAndOperStatusFlags, row.InterfaceGuid.String())
		}
	}
	words := make([]uint64, 16384)
	size := uint32(len(words) * 8)
	first := (*windows.IpAdapterAddresses)(unsafe.Pointer(&words[0]))
	if err := windows.GetAdaptersAddresses(windows.AF_UNSPEC, 0x100, 0, first, &size); err != nil {
		t.Log("native address inventory", err)
		return
	}
	for a := first; a != nil; a = a.Next {
		if a.IfIndex == previous || windows.UTF16PtrToString(a.FriendlyName) == "NetSwitch" {
			t.Logf("native address adapter: index=%d alias=%q status=%d", a.IfIndex, windows.UTF16PtrToString(a.FriendlyName), a.OperStatus)
		}
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
			present, err := nativeAdapterPresent(row.InterfaceGuid)
			if err != nil {
				return 0, 0, err
			}
			if !present {
				index = 0
			}
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

// IP Helper retains phantom interface rows after device removal. Presence is
// a PnP property, not an OperStatus test: disabled live devices still count.
// The installed precondition uses this exact lookup before any fault.
func nativeAdapterPresent(target windows.GUID) (bool, error) {
	class, err := windows.GUIDFromString("{4d36e972-e325-11ce-bfc1-08002be10318}")
	if err != nil {
		return false, err
	}
	devices, err := windows.SetupDiGetClassDevsEx(&class, "", 0, windows.DIGCF_PRESENT, 0, "")
	if err != nil {
		return false, err
	}
	defer windows.SetupDiDestroyDeviceInfoList(devices)
	for i := 0; ; i++ {
		device, err := devices.EnumDeviceInfo(i)
		if errors.Is(err, windows.ERROR_NO_MORE_ITEMS) {
			return false, nil
		}
		if err != nil {
			return false, err
		}
		h, err := devices.OpenDevRegKey(device, windows.DICS_FLAG_GLOBAL, 0, windows.DIREG_DRV, registry.QUERY_VALUE)
		if errors.Is(err, windows.ERROR_FILE_NOT_FOUND) {
			continue
		}
		if err != nil {
			return false, err
		}
		key := registry.Key(h)
		id, _, err := key.GetStringValue("NetCfgInstanceId")
		key.Close()
		if errors.Is(err, registry.ErrNotExist) {
			continue
		}
		if err != nil {
			return false, err
		}
		if strings.EqualFold(id, target.String()) {
			return true, nil
		}
	}
}
