//go:build windows

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
	"unsafe"

	"github.com/AyoubAchour/net-switch/internal/wintun"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// Read-only observer in a separate hosted helper: it outlives engine stop and
// never extends the engine's stop budget or changes its ownership verdict.
func observeRetirement() error {
	started := time.Now()
	for {
		record := map[string]any{"elapsedMs": time.Since(started).Milliseconds()}
		found := false
		for _, level := range []uint32{windows.MibIfTableNormal, windows.MibIfTableRaw} {
			var table *windows.MibIfTable2
			if err := windows.GetIfTable2Ex(level, &table); err != nil {
				return err
			}
			rows := []map[string]any{}
			for _, row := range unsafe.Slice(&table.Table[0], table.NumEntries) {
				if !strings.EqualFold(row.InterfaceGuid.String(), wintun.DefaultGUID) {
					continue
				}
				found = true
				flags := map[string]bool{}
				for bit, name := range []string{"HardwareInterface", "FilterInterface", "ConnectorPresent", "NotAuthenticated", "NotMediaConnected", "Paused", "LowPower", "EndPointInterface"} {
					flags[name] = row.InterfaceAndOperStatusFlags&(1<<bit) != 0
				}
				entry := map[string]any{"luid": row.InterfaceLuid, "guid": row.InterfaceGuid.String(), "alias": windows.UTF16ToString(row.Alias[:]), "type": row.Type,
					"operStatus": row.OperStatus, "adminStatus": row.AdminStatus, "mediaConnectState": row.MediaConnectState, "flags": flags}
				for _, family := range []uint16{windows.AF_INET, windows.AF_INET6} {
					iface := windows.MibIpInterfaceRow{Family: family, InterfaceLuid: row.InterfaceLuid}
					err := windows.GetIpInterfaceEntry(&iface)
					entry[fmt.Sprintf("ipInterface%d", family)] = map[string]any{"present": err == nil, "error": fmt.Sprint(err)}
				}
				var addresses *windows.MibUnicastIpAddressTable
				if err := windows.GetUnicastIpAddressTable(windows.AF_UNSPEC, &addresses); err != nil {
					entry["addressError"] = err.Error()
				} else {
					count := 0
					for _, address := range unsafe.Slice(&addresses.Table[0], addresses.NumEntries) {
						if address.InterfaceLuid == row.InterfaceLuid {
							count++
						}
					}
					entry["addressCount"] = count
					windows.FreeMibTable(unsafe.Pointer(addresses))
				}
				rows = append(rows, entry)
			}
			windows.FreeMibTable(unsafe.Pointer(table))
			record[fmt.Sprintf("table%d", level)] = rows
		}
		present, err := retirementPnPPresent()
		record["pnpPresent"], record["pnpError"] = present, fmt.Sprint(err)
		record["utc"] = time.Now().UTC().Format(time.RFC3339Nano)
		data, err := json.Marshal(record)
		if err != nil {
			return err
		}
		fmt.Printf("ADAPTER_VIEW %s\n", data)
		if !found || time.Since(started) >= 30*time.Second {
			return nil // Observation, never an alternate cleanup verdict.
		}
		time.Sleep(500 * time.Millisecond)
	}
}

func retirementPnPPresent() (bool, error) {
	class, err := windows.GUIDFromString("{4D36E972-E325-11CE-BFC1-08002BE10318}")
	if err != nil {
		return false, err
	}
	set, err := windows.SetupDiGetClassDevsEx(&class, "SWD\\Wintun", 0, windows.DIGCF_PRESENT, 0, "")
	if err != nil {
		return false, err
	}
	defer set.Close()
	for i := 0; ; i++ {
		device, err := set.EnumDeviceInfo(i)
		if errors.Is(err, windows.ERROR_NO_MORE_ITEMS) {
			return false, nil
		}
		if err != nil {
			return false, err
		}
		key, err := set.OpenDevRegKey(device, windows.DICS_FLAG_GLOBAL, 0, windows.DIREG_DRV, windows.KEY_QUERY_VALUE)
		if err != nil {
			return false, err // An unreadable device is not proof of absence.
		}
		id, _, err := registry.Key(key).GetStringValue("NetCfgInstanceId")
		registry.Key(key).Close()
		if err != nil {
			return false, err
		}
		if strings.EqualFold(id, wintun.DefaultGUID) {
			// Capture the device's native name before removal; later file-handle
			// names can be compared without opening the Wintun device ourselves.
			object, objectErr := set.DeviceRegistryProperty(device, windows.SPDRP_PHYSICAL_DEVICE_OBJECT_NAME)
			instance, instanceErr := set.DeviceInstanceID(device)
			interfaceClass, _ := windows.GUIDFromString("{CAC88484-7515-4C03-82E6-71A87ABAC361}")
			paths, pathErr := windows.CM_Get_Device_Interface_List(instance, &interfaceClass, windows.CM_GET_DEVICE_INTERFACE_LIST_PRESENT)
			referenceRecord("pnp-device", map[string]any{"guid": id, "deviceObject": object, "objectError": fmt.Sprint(objectErr), "instance": instance, "instanceError": fmt.Sprint(instanceErr), "devicePaths": paths, "devicePathError": fmt.Sprint(pathErr)})
			return true, nil
		}
	}
}
