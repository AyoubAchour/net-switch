//go:build windows

package winengine

import (
	"errors"
	"fmt"
	"strings"
	"unsafe"

	"github.com/AyoubAchour/net-switch/internal/wintun"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

type adapterRow struct {
	guid, alias string
	luid        uint64
}

// One rule for retirement and creation. An NDIS row can outlive PnP and IP
// because other applications' TIME_WAIT TCBs retain it. Its status is irrelevant.
// Only the recorded LUID may be ignored; unknown/replacement rows fail closed.
func adapterPresent(guid, alias string, luid uint64, rows []adapterRow, pnp func() (bool, error), ip func(uint64, uint16) error) (bool, error) {
	for _, row := range rows {
		if strings.EqualFold(row.guid, guid) || row.alias == alias {
			if luid == 0 || row.luid != luid || !strings.EqualFold(row.guid, guid) {
				return true, errors.New("foreign or replacement adapter identity")
			}
		}
	}
	present, err := pnp()
	if err != nil || present {
		return true, err
	}
	if luid == 0 {
		return false, nil
	} // No prior identity and no matching row.
	for _, family := range []uint16{windows.AF_INET, windows.AF_INET6} {
		err := ip(luid, family)
		if err == nil {
			return true, nil
		}
		if !errors.Is(err, windows.ERROR_NOT_FOUND) && !errors.Is(err, windows.ERROR_FILE_NOT_FOUND) {
			return true, err
		}
	}
	return false, nil
}

// LeftoverAdapterPresent applies the same absence rule for a harness adapter
// whose previous owner process is gone and left no LUID history (TestISP). A
// row with our GUID or alias is judged by its own LUID: present only while
// its PnP devnode exists or an IP interface still exists for that LUID. A
// lingering NDIS row kept alive by other apps' TIME_WAIT entries is absent.
// Rows with a different GUID under our alias still count as present. The
// reason names what was seen, so a refusal is never silent.
func LeftoverAdapterPresent(guid, alias string) (present bool, reason string, err error) {
	rows, err := nativeAdapterRows()
	if err != nil {
		return true, "interface table unreadable", err
	}
	return leftoverAdapterPresent(guid, alias, rows, func() (bool, error) { return presentWintunDevice(guid) }, nativeIPInterface)
}

func leftoverAdapterPresent(guid, alias string, rows []adapterRow, pnp func() (bool, error), ip func(uint64, uint16) error) (bool, string, error) {
	matched := []adapterRow{}
	for _, row := range rows {
		if strings.EqualFold(row.guid, guid) || row.alias == alias {
			if !strings.EqualFold(row.guid, guid) {
				return true, fmt.Sprintf("foreign adapter %s uses alias %q (luid %d)", row.guid, row.alias, row.luid), errors.New("foreign or replacement adapter identity")
			}
			matched = append(matched, row)
		}
	}
	devnode, err := pnp()
	if err != nil {
		return true, fmt.Sprintf("PnP query for %s failed", guid), err
	}
	if devnode {
		return true, fmt.Sprintf("PnP devnode SWD\\Wintun\\%s is present", guid), nil
	}
	for _, row := range matched {
		for _, family := range []uint16{windows.AF_INET, windows.AF_INET6} {
			err := ip(row.luid, family)
			if err == nil {
				return true, fmt.Sprintf("IP interface family %d still exists for luid %d (%s)", family, row.luid, row.guid), nil
			}
			if !errors.Is(err, windows.ERROR_NOT_FOUND) && !errors.Is(err, windows.ERROR_FILE_NOT_FOUND) {
				return true, fmt.Sprintf("IP interface query failed for luid %d family %d", row.luid, family), err
			}
		}
	}
	if len(matched) > 0 {
		return false, fmt.Sprintf("only a lingering interface row (luid %d) with no device or IP interface", matched[0].luid), nil
	}
	return false, "no row, device or IP interface", nil
}

func nativeAdapterPresent(guid, alias string, luid uint64) (bool, error) {
	rows, err := nativeAdapterRows()
	if err != nil {
		return true, err
	}
	return adapterPresent(guid, alias, luid, rows, func() (bool, error) { return presentWintunDevice(guid) }, nativeIPInterface)
}

func nativeIPInterface(luid uint64, family uint16) error {
	row := windows.MibIpInterfaceRow{Family: family, InterfaceLuid: luid}
	return windows.GetIpInterfaceEntry(&row)
}

func nativeAdapterRows() ([]adapterRow, error) {
	var table *windows.MibIfTable2
	if err := windows.GetIfTable2Ex(windows.MibIfTableNormal, &table); err != nil {
		return nil, err
	}
	rows := make([]adapterRow, 0, table.NumEntries)
	for _, r := range unsafe.Slice(&table.Table[0], table.NumEntries) {
		rows = append(rows, adapterRow{r.InterfaceGuid.String(), windows.UTF16ToString(r.Alias[:]), r.InterfaceLuid})
	}
	windows.FreeMibTable(unsafe.Pointer(table))
	return rows, nil
}

func presentWintunDevice(guid string) (bool, error) {
	return inspectWintunDevice(guid, false)
}

func inspectWintunDevice(guid string, exact bool) (bool, error) {
	class, _ := windows.GUIDFromString("{4D36E972-E325-11CE-BFC1-08002BE10318}")
	set, err := windows.SetupDiGetClassDevsEx(&class, "SWD\\Wintun", 0, windows.DIGCF_PRESENT, 0, "")
	if err != nil {
		return true, err
	}
	defer set.Close()
	for i := 0; ; i++ {
		device, err := set.EnumDeviceInfo(i)
		if errors.Is(err, windows.ERROR_NO_MORE_ITEMS) {
			return false, nil
		}
		if err != nil {
			return true, err
		}
		instance, instanceErr := set.DeviceInstanceID(device)
		if instanceErr != nil {
			instance = fmt.Sprintf("devinst:%d", device.DevInst)
		}
		id := ""
		key, readErr := set.OpenDevRegKey(device, windows.DICS_FLAG_GLOBAL, 0, windows.DIREG_DRV, windows.KEY_QUERY_VALUE)
		if readErr == nil {
			id, _, readErr = registry.Key(key).GetStringValue("NetCfgInstanceId")
			registry.Key(key).Close()
		}
		present, err := wintunDeviceMatches(guid, instance, id, instanceErr, readErr)
		if exact && present && err == nil && (instanceErr != nil || !strings.EqualFold(instance, "SWD\\WINTUN\\"+guid)) {
			return true, fmt.Errorf("recovery device instance does not match journal GUID: %q", instance)
		}
		if present || err != nil {
			return true, err
		}
	}
}

// Called only while replaying a durable adapter record under the lifetime lock,
// never from the create guard or while an in-process adapter handle is live.
func recoveredAdapterLUID(guid, alias string, prior uint64, rows []adapterRow, exactDevice func() (bool, error), ip func(uint64, uint16) error) (uint64, bool, error) {
	var candidate uint64
	for _, row := range rows {
		if row.alias == alias && !strings.EqualFold(row.guid, guid) {
			return 0, false, errors.New("foreign adapter alias during journal recovery")
		}
		if !strings.EqualFold(row.guid, guid) {
			continue
		}
		if row.luid == 0 || (candidate != 0 && candidate != row.luid) {
			return 0, false, errors.New("ambiguous adapter rows during journal recovery")
		}
		candidate = row.luid
	}
	if candidate == 0 {
		return prior, false, nil
	}
	present, err := exactDevice()
	if err != nil {
		return 0, false, err
	}
	if present {
		return candidate, true, nil
	}
	// No device exists. Only a fully retired exact-GUID row can supply the
	// missing historical identity; a functioning IP interface is not adopted.
	stillPresent, err := adapterPresent(guid, alias, candidate, rows, func() (bool, error) { return false, nil }, ip)
	if err != nil {
		return 0, false, err
	}
	if stillPresent {
		return 0, false, errors.New("IP interface remains without verified recovery device")
	}
	return candidate, false, nil
}

// Wintun uses the requested GUID as the software-device instance ID. Only
// that exact, parseable form proves an unreadable device belongs elsewhere.
// A readable registry identity remains authoritative even if the instance
// string differs (including older or unexpected device naming conventions).
func wintunDeviceMatches(guid, instance, id string, instanceErr, readErr error) (bool, error) {
	if readErr == nil {
		parsed, err := windows.GUIDFromString(id)
		if err == nil {
			return strings.EqualFold(parsed.String(), guid), nil
		}
		readErr = fmt.Errorf("invalid NetCfgInstanceId: %w", err)
	}
	const prefix = "SWD\\WINTUN\\"
	if instanceErr == nil && len(instance) > len(prefix) && strings.EqualFold(instance[:len(prefix)], prefix) {
		parsed, err := windows.GUIDFromString(instance[len(prefix):])
		if err == nil && !strings.EqualFold(parsed.String(), guid) {
			return false, nil
		}
	}
	return true, fmt.Errorf("cannot identify present Wintun device %q: %w", instance, errors.Join(instanceErr, readErr))
}

func (o *objects) rememberAdapter(luid uint64) error {
	if luid == 0 {
		return errors.New("adapter has zero LUID")
	}
	previous := o.adapterLUID
	if o.saveAdapterLUID != nil {
		if err := o.saveAdapterLUID(luid); err != nil {
			return fmt.Errorf("persist adapter identity: %w", err)
		}
	}
	o.adapterLUID = luid
	if hostedTraceEnabled() {
		fmt.Printf("WINDOWS ADAPTER ARRIVAL previous_luid=%d luid=%d reused=%t guid=%s\n", previous, luid, previous == luid, wintun.DefaultGUID)
	}
	return nil
}
