package winplatform

import (
	"debug/pe"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"path/filepath"
	"strings"
	"unsafe"

	js "github.com/AyoubAchour/net-switch/internal/jsvalue"
	"github.com/AyoubAchour/net-switch/internal/platform"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

func Execute(operation string, a map[string]any) (any, error) {
	switch operation {
	case "line-check":
		return checkLine(uint32(js.Number(a["index"])), js.Text(a["target"]), a["quick"] == true, a["custom"] == true), nil
	case "network":
		return readNetwork()
	case "tcp-port-configuration":
		return readTCPPortSettings()
	case "architecture":
		return Architecture()
	case "policy":
		v, err := readPolicy()
		if v == "absent" {
			v = nil
		}
		return v, err
	case "policy-set":
		return nil, writePolicy(a["value"])
	case "metrics":
		return readMetrics(js.Text(a["alias"]))
	case "metrics-set", "metrics-restore":
		key := "before"
		if operation == "metrics-restore" {
			key = "metrics"
		}
		rows, _ := a[key].([]any)
		if len(rows) == 0 {
			return nil, fmt.Errorf("no saved metric families")
		}
		for _, v := range rows {
			m := js.Object(v)
			auto := m["automatic"] == true
			value := uint32(js.Number(m["metric"]))
			if operation == "metrics-set" {
				auto = false
				value = uint32(js.Number(a["metric"]))
			}
			if err := writeMetric(js.Text(a["alias"]), js.Text(m["family"]), auto, value); err != nil {
				return nil, err
			}
		}
		return nil, nil
	case "protect-directory":
		return nil, ProtectDirectory(js.Text(a["path"]))
	case "port-holder":
		return portHolder(uint16(js.Number(a["port"])))
	case "stop-process":
		return nil, StopProcess(uint32(js.Number(a["pid"])), js.Text(a["path"]))
	case "close-tcp":
		b, err := json.Marshal(a["connections"])
		if err != nil {
			return nil, err
		}
		var tuples []platform.TCPSelector
		if err := json.Unmarshal(b, &tuples); err != nil {
			return nil, err
		}
		return closeTCP(tuples)
	case "tcp-identity":
		rows, err := tcpConnections()
		if err != nil {
			return nil, err
		}
		out := []map[string]any{}
		for _, r := range rows {
			if r.localPort == uint16(js.Number(a["port"])) {
				out = append(out, map[string]any{"local": netip.AddrFrom4(r.local).String(), "lport": r.localPort, "remote": netip.AddrFrom4(r.remote).String(), "rport": r.remotePort, "pid": r.pid, "created": formatCreated(r.created), "processStarted": processStarted(r.pid), "state": r.state})
			}
		}
		return out, nil
	case "app-info":
		paths := []string{}
		for _, v := range arrayValue(a["paths"]) {
			paths = append(paths, js.Text(v))
		}
		return comThread(func() (any, error) { return appInformation(paths), nil })
	case "installed-apps":
		return installedApps()
	case "autostart":
		return taskEnabled()
	case "autostart-set":
		return nil, setTasks(a)
	case "autostart-upgrade":
		return upgradeTask(a)
	default:
		return nil, fmt.Errorf("unknown Windows operation %q", operation)
	}
}
func ControlElevated() (bool, error) {
	return windows.GetCurrentProcessToken().IsElevated(), nil
}
func ProgramFiles() (string, error) {
	return windows.KnownFolderPath(windows.FOLDERID_ProgramFiles, 0)
}
func arrayValue(v any) []any { a, _ := v.([]any); return a }
func Architecture() (string, error) {
	var process, native uint16
	if err := windows.IsWow64Process2(windows.CurrentProcess(), &process, &native); err != nil {
		return "", err
	}
	switch native {
	case pe.IMAGE_FILE_MACHINE_ARM64:
		return "arm64", nil
	case pe.IMAGE_FILE_MACHINE_AMD64:
		return "x64", nil
	case pe.IMAGE_FILE_MACHINE_I386:
		return "ia32", nil
	}
	return "", fmt.Errorf("unknown Windows machine 0x%x", native)
}
func findInterface(alias string) (*windows.MibIfRow2, error) {
	var table *windows.MibIfTable2
	if err := windows.GetIfTable2Ex(windows.MibIfTableNormal, &table); err != nil {
		return nil, err
	}
	defer windows.FreeMibTable(unsafe.Pointer(table))
	for _, row := range unsafe.Slice(&table.Table[0], table.NumEntries) {
		if windows.UTF16ToString(row.Alias[:]) == alias {
			return &row, nil
		}
	}
	return nil, windows.ERROR_NOT_FOUND
}
func familyNumber(name string) (uint16, error) {
	switch name {
	case "IPv4":
		return windows.AF_INET, nil
	case "IPv6":
		return windows.AF_INET6, nil
	}
	return 0, fmt.Errorf("unknown address family %s", name)
}
func readMetrics(alias string) ([]map[string]any, error) {
	i, err := findInterface(alias)
	if err != nil {
		return nil, err
	}
	result := []map[string]any{}
	for _, name := range []string{"IPv4", "IPv6"} {
		family, _ := familyNumber(name)
		row := windows.MibIpInterfaceRow{Family: family, InterfaceLuid: i.InterfaceLuid}
		if err := windows.GetIpInterfaceEntry(&row); err != nil {
			if missingIPInterface(err) {
				continue
			}
			return nil, err
		}
		result = append(result, map[string]any{"family": name, "automatic": row.UseAutomaticMetric != 0, "metric": row.Metric})
	}
	if len(result) == 0 {
		return nil, fmt.Errorf("Windows did not return valid interface metrics for %q", alias)
	}
	return result, nil
}
func writeMetric(alias, family string, automatic bool, metric uint32) error {
	i, err := findInterface(alias)
	if err != nil {
		return err
	}
	f, err := familyNumber(family)
	if err != nil {
		return err
	}
	row := windows.MibIpInterfaceRow{Family: f, InterfaceLuid: i.InterfaceLuid}
	if err := windows.GetIpInterfaceEntry(&row); err != nil {
		return err
	}
	before := row
	row.UseAutomaticMetric = 0
	if automatic {
		row.UseAutomaticMetric = 1
	} else {
		row.Metric = metric
	}
	// The SDK requires SitePrefixLength=0 for IPv4 when writing the row.
	if f == windows.AF_INET {
		row.SitePrefixLength = 0
	}
	set := func(r *windows.MibIpInterfaceRow) error {
		code, _, _ := iphlpapi.NewProc("SetIpInterfaceEntry").Call(uintptr(unsafe.Pointer(r)))
		if code != 0 {
			return windows.Errno(code)
		}
		return nil
	}
	if err := set(&row); err != nil {
		return err
	}
	if err := persistMetric(i.InterfaceIndex, f, automatic, metric); err != nil {
		if f == windows.AF_INET {
			before.SitePrefixLength = 0
		}
		rollback := set(&before)
		return fmt.Errorf("persist %s metric: %w (active rollback: %v)", family, err, rollback)
	}
	return nil
}

const policySubkey = `SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy`

func writePolicy(value any) error {
	if value == nil {
		k, err := registry.OpenKey(registry.LOCAL_MACHINE, policySubkey, registry.SET_VALUE)
		if errors.Is(err, registry.ErrNotExist) {
			return nil
		}
		if err != nil {
			return err
		}
		defer k.Close()
		err = k.DeleteValue("fMinimizeConnections")
		if errors.Is(err, registry.ErrNotExist) {
			return nil
		}
		return err
	}
	k, _, err := registry.CreateKey(registry.LOCAL_MACHINE, policySubkey, registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer k.Close()
	return k.SetDWordValue("fMinimizeConnections", uint32(js.Number(value)))
}

func StopProcess(pid uint32, path string) error {
	if pid == 0 || !filepath.IsAbs(path) {
		return fmt.Errorf("stop requires a PID and absolute executable path")
	}
	// A reused PID may now be a protected SYSTEM process. Identify with only
	// query rights first; an unreadable identity is not evidence of our engine.
	query, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return nil
	}
	defer windows.CloseHandle(query)
	buf := make([]uint16, windows.MAX_LONG_PATH)
	size := uint32(len(buf))
	if err := windows.QueryFullProcessImageName(query, 0, &buf[0], &size); err != nil {
		return nil
	}
	if !strings.EqualFold(windows.UTF16ToString(buf[:size]), path) {
		return nil
	}
	// Keep the query handle open so this process object (and PID) cannot be
	// recycled between identity verification and opening terminate rights.
	h, err := windows.OpenProcess(windows.PROCESS_TERMINATE|windows.SYNCHRONIZE, false, pid)
	if errors.Is(err, windows.ERROR_INVALID_PARAMETER) {
		return nil
	}
	if err != nil {
		return err
	}
	defer windows.CloseHandle(h)
	if err := windows.TerminateProcess(h, 1); err != nil {
		return err
	}
	event, err := windows.WaitForSingleObject(h, 8000)
	if err != nil {
		return err
	}
	if event != windows.WAIT_OBJECT_0 {
		return fmt.Errorf("process %d did not stop", pid)
	}
	return nil
}
func portHolder(port uint16) (any, error) {
	rows, err := tcpTable(8)
	if err != nil {
		return nil, err
	}
	for _, r := range rows {
		if r.local == [4]byte{127, 0, 0, 1} && r.localPort == port && r.state == 2 {
			path := processPath(r.pid)
			if path != "" {
				return map[string]any{"pid": r.pid, "image": strings.ToLower(filepath.Base(path))}, nil
			}
		}
	}
	return nil, nil
}
func closeTCP(tuples []platform.TCPSelector) (map[string]any, error) {
	closed, failed, gone := 0, 0, 0
	codes := []uint32{}
	for _, t := range tuples {
		rows, err := tcpConnections()
		if err != nil {
			return nil, err
		}
		var found *tcpConnection
		for _, r := range rows {
			if r.state == tcpStateEstablished && r.pid == uint32(t.PID) && r.localPort == uint16(t.LPort) && r.remotePort == uint16(t.RPort) && netip.AddrFrom4(r.local).String() == t.Local && netip.AddrFrom4(r.remote).String() == t.Remote && formatCreated(r.created) == t.Created {
				found = &r
				break
			}
		}
		if found == nil {
			gone++
			continue
		}
		owner, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, found.pid)
		if err != nil {
			gone++
			continue
		}
		started, err := processCreationTime(owner)
		if err != nil || started > found.created || (t.ProcessStarted != "" && formatCreated(started) != t.ProcessStarted) {
			windows.CloseHandle(owner)
			gone++
			continue
		}
		row := found.row()
		row.State = 12
		code, _, _ := iphlpapi.NewProc("SetTcpEntry").Call(uintptr(unsafe.Pointer(&row)))
		windows.CloseHandle(owner)
		if code == 0 {
			closed++
		} else {
			failed++
			codes = append(codes, uint32(code))
		}
	}
	return map[string]any{"closed": closed, "failed": failed, "gone": gone, "codes": codes}, nil
}
