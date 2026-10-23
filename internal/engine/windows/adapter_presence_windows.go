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

func nativeAdapterPresent(guid, alias string, luid uint64) (bool, error) {
	var table *windows.MibIfTable2
	if err := windows.GetIfTable2Ex(windows.MibIfTableNormal, &table); err != nil {
		return true, err
	}
	rows := make([]adapterRow, 0, table.NumEntries)
	for _, r := range unsafe.Slice(&table.Table[0], table.NumEntries) {
		rows = append(rows, adapterRow{r.InterfaceGuid.String(), windows.UTF16ToString(r.Alias[:]), r.InterfaceLuid})
	}
	windows.FreeMibTable(unsafe.Pointer(table))
	return adapterPresent(guid, alias, luid, rows, func() (bool, error) { return presentWintunDevice(guid) }, func(luid uint64, family uint16) error {
		row := windows.MibIpInterfaceRow{Family: family, InterfaceLuid: luid}
		return windows.GetIpInterfaceEntry(&row)
	})
}

func presentWintunDevice(guid string) (bool, error) {
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
		if present || err != nil {
			return true, err
		}
	}
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
	o.adapterLUID = luid
	if o.saveAdapterLUID != nil {
		if err := o.saveAdapterLUID(luid); err != nil {
			return fmt.Errorf("persist adapter identity: %w", err)
		}
	}
	if hostedTraceEnabled() {
		fmt.Printf("WINDOWS ADAPTER ARRIVAL previous_luid=%d luid=%d reused=%t guid=%s\n", previous, luid, previous == luid, wintun.DefaultGUID)
	}
	return nil
}
