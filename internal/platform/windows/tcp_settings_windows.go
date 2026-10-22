package winplatform

import "fmt"

// TCPPortSetting preserves null properties for templates which inherit their
// range. The values come from the documented MSFT_NetTCPSetting provider.
// https://learn.microsoft.com/windows/win32/fwp/wmi/nettcpipprov/msft-nettcpsetting
type TCPPortSetting struct {
	SettingName                     string
	DynamicPortRangeStartPort       *uint32
	DynamicPortRangeNumberOfPorts   *uint32
	AutoReusePortRangeStartPort     *uint32
	AutoReusePortRangeNumberOfPorts *uint32
}

// readTCPPortSettings runs only in a disposable, supervised read worker. WMI
// calls may block; the parent owns the deadline and the worker's kill-on-close job.
func readTCPPortSettings() (any, error) {
	return comThread(func() (any, error) {
		locator, err := comCreate("{76a64158-cb41-11d1-8b02-00600806d9b6}", &iidDispatch)
		if err != nil {
			return nil, err
		}
		defer locator.release()
		service, err := locator.object("ConnectServer", 1, ".", `root\StandardCimv2`)
		if err != nil {
			return nil, err
		}
		defer service.release()
		set, err := service.object("ExecQuery", 1,
			"SELECT SettingName,DynamicPortRangeStartPort,DynamicPortRangeNumberOfPorts,AutoReusePortRangeStartPort,AutoReusePortRangeNumberOfPorts FROM MSFT_NetTCPSetting", "WQL", 0)
		if err != nil {
			return nil, err
		}
		defer set.release()
		count, err := set.number("Count")
		if err != nil {
			return nil, err
		}
		if count <= 0 || count > 256 {
			return nil, fmt.Errorf("unexpected TCP setting count %d", count)
		}
		rows := make([]TCPPortSetting, 0, count)
		for i := 0; i < count; i++ {
			item, err := set.object("ItemIndex", 1, i)
			if err != nil {
				return nil, err
			}
			row, err := tcpPortSetting(item)
			item.release()
			if err != nil {
				return nil, err
			}
			rows = append(rows, row)
		}
		return rows, nil
	})
}

func tcpPortSetting(item *comObject) (row TCPPortSetting, err error) {
	row.SettingName, err = item.text("SettingName")
	if err != nil {
		return row, err
	}
	for _, property := range []struct {
		name string
		dest **uint32
	}{
		{"DynamicPortRangeStartPort", &row.DynamicPortRangeStartPort},
		{"DynamicPortRangeNumberOfPorts", &row.DynamicPortRangeNumberOfPorts},
		{"AutoReusePortRangeStartPort", &row.AutoReusePortRangeStartPort},
		{"AutoReusePortRangeNumberOfPorts", &row.AutoReusePortRangeNumberOfPorts},
	} {
		v, err := item.call(property.name, 2)
		if err != nil {
			return row, err
		}
		switch v.vt {
		case 0, 1: // VT_EMPTY / VT_NULL: inherited, not a made-up zero.
		case 2, 3, 17, 18, 19, 22, 23:
			value := uint32(v.data)
			if value > 65535 {
				err = fmt.Errorf("invalid %s: %d", property.name, value)
			} else {
				*property.dest = &value
			}
		default:
			err = fmt.Errorf("%s is not an integer or null (variant %d)", property.name, v.vt)
		}
		v.clear()
		if err != nil {
			return row, err
		}
	}
	return row, nil
}
