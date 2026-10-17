package main

import (
	"errors"
	"fmt"
	"math"
	"net/netip"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

type networkAdapter struct {
	Alias           string   `json:"alias"`
	GUID            string   `json:"guid"`
	MAC             string   `json:"mac"`
	Index           uint32   `json:"index"`
	Description     string   `json:"description"`
	Status          string   `json:"status"`
	MediaType       string   `json:"mediaType"`
	LinkSpeed       string   `json:"linkSpeed"`
	Virtual         bool     `json:"virtual"`
	Gateway         *string  `json:"gateway"`
	RouteMetric     *uint32  `json:"routeMetric"`
	IPv4            *string  `json:"ipv4"`
	IPv4s           []string `json:"ipv4s"`
	Metric          *uint32  `json:"metric"`
	AutomaticMetric *bool    `json:"automaticMetric"`
	SSID            *string  `json:"ssid"`
}

type defaultRoute struct {
	Gateway          string `json:"gateway"`
	InterfaceAddress string `json:"interfaceAddress"`
	Metric           uint32 `json:"metric"`
}

type networkLine struct {
	ReadAt        int64            `json:"readAt"`
	Adapters      []networkAdapter `json:"adapters"`
	DefaultRoutes []defaultRoute   `json:"defaultRoutes"`
	Policy        any              `json:"policy"`
}

func adapterStatus(row *windows.MibIfRow2) string {
	// Match NetAdapter.Types.ps1xml, including combined reasons for being down.
	switch row.OperStatus {
	case 1:
		return "Up"
	case 2:
		if row.AdminStatus == 2 {
			return "Disabled"
		}
		reasons := []string{}
		for _, reason := range []struct {
			flag uint8
			text string
		}{
			{8, "Not Authenticated"}, {16, "Disconnected"}, {64, "Low Power State"},
		} {
			if row.InterfaceAndOperStatusFlags&reason.flag != 0 {
				reasons = append(reasons, reason.text)
			}
		}
		return strings.Join(reasons, ", ")
	case 3:
		return "Testing"
	case 4:
		return "Unknown"
	case 6:
		return "Not Present"
	case 5:
		return "Dormant"
	case 7:
		return "Lower Layer Down"
	}
	return ""
}

func mediaType(value uint32) string {
	names := map[uint32]string{
		0: "Unspecified", 1: "Wireless LAN", 2: "Cable Modem", 8: "Wireless WAN",
		9: "Native 802.11", 10: "BlueTooth", 11: "Infiniband", 12: "WiMAX",
		13: "UWB", 14: "802.3", 16: "IRDA", 17: "Wired WAN", 18: "Wired Connection Oriented WAN", 19: "Other",
	}
	if name, ok := names[value]; ok {
		return name
	}
	return "Unknown"
}

func linkSpeed(speed uint64) string {
	units := []string{"bps", "Kbps", "Mbps", "Gbps", "Tbps"}
	value, unit := float64(speed), 0
	for value >= 1000 && unit < len(units)-1 {
		value /= 1000
		unit++
	}
	// PowerShell's Format-LinkSpeed rounds to one decimal, with ties to even.
	return strconv.FormatFloat(math.RoundToEven(value*10)/10, 'f', -1, 64) + " " + units[unit]
}

func readPolicy() (any, error) {
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy`, registry.QUERY_VALUE)
	if errors.Is(err, registry.ErrNotExist) {
		return "absent", nil
	}
	if err != nil {
		return nil, err
	}
	defer key.Close()
	return policyValue(key)
}

type policyKey interface {
	GetIntegerValue(string) (uint64, uint32, error)
	GetStringValue(string) (string, uint32, error)
}

func policyValue(key policyKey) (any, error) {
	value, _, err := key.GetIntegerValue("fMinimizeConnections")
	if errors.Is(err, registry.ErrNotExist) {
		return "absent", nil
	}
	if errors.Is(err, registry.ErrUnexpectedType) {
		text, kind, err := key.GetStringValue("fMinimizeConnections")
		if err != nil {
			return nil, err
		}
		if kind != registry.SZ {
			return nil, registry.ErrUnexpectedType
		}
		number, err := strconv.ParseInt(strings.TrimSpace(text), 10, 32)
		if err != nil {
			return nil, err
		}
		return int32(number), nil
	}
	if err != nil {
		return nil, err
	}
	return int32(value), nil
}

const networkDeviceClass = "{4d36e972-e325-11ce-bfc1-08002be10318}"

// GetIfTable2 also retains interfaces for removed PnP devices (for example
// old Hyper-V NICs in an Azure VM image). Get-NetAdapter omits those even
// with -IncludeHidden. Check PnP presence, not OperStatus: a present but
// disabled adapter can report Not Present too and must remain in the list.
// https://learn.microsoft.com/windows-hardware/drivers/install/determining-whether-a-device-is-plugged-in
func phantomAdapterDrivers() (map[string]bool, error) {
	guid, err := windows.GUIDFromString(networkDeviceClass)
	if err != nil {
		return nil, err
	}
	devices, err := windows.SetupDiGetClassDevsEx(&guid, "", 0, 0, 0, "")
	if err != nil {
		return nil, err
	}
	defer windows.SetupDiDestroyDeviceInfoList(devices)
	phantoms := map[string]bool{}
	for i := 0; ; i++ {
		device, err := windows.SetupDiEnumDeviceInfo(devices, i)
		if errors.Is(err, windows.ERROR_NO_MORE_ITEMS) {
			break
		}
		if err != nil {
			return nil, err
		}
		var status, problem uint32
		err = windows.CM_Get_DevNode_Status(&status, &problem, device.DevInst, 0)
		if err == nil {
			continue
		}
		if !errors.Is(err, windows.CR_NO_SUCH_DEVINST) {
			return nil, fmt.Errorf("read PnP device status: %w", err)
		}
		driver, err := windows.SetupDiGetDeviceRegistryProperty(devices, device, windows.SPDRP_DRIVER)
		if errors.Is(err, windows.ERROR_INVALID_DATA) {
			continue // An unconfigured device has no driver/interface to exclude.
		}
		if err != nil {
			return nil, fmt.Errorf("read phantom adapter driver: %w", err)
		}
		name, ok := driver.(string)
		if !ok {
			return nil, fmt.Errorf("unexpected adapter driver property type %T", driver)
		}
		phantoms[strings.ToLower(name)] = true
	}
	return phantoms, nil
}

// Exclude NCF_HIDDEN devices and phantom PnP devices. Do not require every
// interface to have a PnP device: Hyper-V virtual ports can lack one.
func hiddenAdapters() (map[string]bool, error) {
	phantoms, err := phantomAdapterDrivers()
	if err != nil {
		return nil, err
	}
	result := map[string]bool{}
	class, err := registry.OpenKey(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Control\Class\`+networkDeviceClass, registry.ENUMERATE_SUB_KEYS)
	if err != nil {
		return nil, err
	}
	defer class.Close()
	names, err := class.ReadSubKeyNames(-1)
	if err != nil {
		return nil, err
	}
	for _, name := range names {
		if len(name) != 4 || strings.Trim(name, "0123456789") != "" {
			continue
		}
		key, err := registry.OpenKey(class, name, registry.QUERY_VALUE)
		if errors.Is(err, registry.ErrNotExist) {
			continue
		}
		if err != nil {
			fmt.Fprintf(os.Stderr, "can't read adapter class subkey %s: %v\n", name, err)
			continue
		}
		guid, _, guidErr := key.GetStringValue("NetCfgInstanceId")
		flags, _, flagsErr := key.GetIntegerValue("Characteristics")
		key.Close()
		if guidErr == nil {
			result[strings.ToLower(guid)] = (flagsErr == nil && flags&8 != 0) || phantoms[networkDeviceClass+`\`+name]
		}
	}
	return result, nil
}

func routeIPv4(address *windows.RawSockaddrInet) string {
	return netip.AddrFrom4((*windows.RawSockaddrInet4)(unsafe.Pointer(address)).Addr).String()
}

func readNetwork() (networkLine, error) {
	line := networkLine{ReadAt: time.Now().UnixMilli(), Adapters: []networkAdapter{}, DefaultRoutes: []defaultRoute{}}
	var err error
	line.Policy, err = readPolicy()
	if err != nil {
		line.Policy = "unknown"
		fmt.Fprintf(os.Stderr, "read Wi-Fi policy: %v\n", err)
	}
	first, err := adapterAddresses(true)
	if err != nil {
		return line, err
	}
	addresses := map[uint32][]string{}
	for adapter := first; adapter != nil; adapter = adapter.Next {
		for unicast := adapter.FirstUnicastAddress; unicast != nil; unicast = unicast.Next {
			ip := unicast.Address.IP()
			if ip.To4() != nil && !ip.IsLinkLocalUnicast() {
				addresses[adapter.IfIndex] = append(addresses[adapter.IfIndex], ip.String())
			}
		}
	}
	var routes *windows.MibIpForwardTable2
	if err := windows.GetIpForwardTable2(windows.AF_INET, &routes); err != nil {
		return line, fmt.Errorf("read routes: %w", err)
	}
	defer windows.FreeMibTable(unsafe.Pointer(routes))
	defaults := []windows.MibIpForwardRow2{}
	for _, route := range routes.Rows() {
		if route.DestinationPrefix.PrefixLength == 0 && routeIPv4(&route.DestinationPrefix.Prefix) == "0.0.0.0" {
			defaults = append(defaults, route)
		}
	}
	ssids := readSSIDs()
	hidden, err := hiddenAdapters()
	if err != nil {
		return line, fmt.Errorf("read adapter visibility: %w", err)
	}
	// Unlike GetAdaptersAddresses, the interface table includes disabled adapters.
	var table *windows.MibIfTable2
	if err := windows.GetIfTable2Ex(windows.MibIfTableNormal, &table); err != nil {
		return line, fmt.Errorf("read interfaces: %w", err)
	}
	defer windows.FreeMibTable(unsafe.Pointer(table))
	return assembleNetwork(line, unsafe.Slice(&table.Table[0], table.NumEntries), addresses, defaults, ssids, hidden, windows.GetIpInterfaceEntry)
}

func vanishedAdapter(err error) bool {
	return errors.Is(err, windows.ERROR_NOT_FOUND) || errors.Is(err, windows.ERROR_FILE_NOT_FOUND)
}

func assembleNetwork(line networkLine, rows []windows.MibIfRow2, addresses map[uint32][]string, defaults []windows.MibIpForwardRow2, ssids map[string]string, hidden map[string]bool, readIP func(*windows.MibIpInterfaceRow) error) (networkLine, error) {
	for _, row := range rows {
		// Get-NetAdapter lists network devices, not loopback, IP tunnels or
		// filter/endpoint interfaces stacked on top of those devices.
		if row.Type == 24 || row.Type == 131 || row.InterfaceAndOperStatusFlags&0x82 != 0 || hidden[strings.ToLower(row.InterfaceGuid.String())] {
			continue
		}
		own := addresses[row.InterfaceIndex]
		if own == nil {
			own = []string{}
		}
		adapter := networkAdapter{
			Alias: windows.UTF16ToString(row.Alias[:]), GUID: strings.ToUpper(row.InterfaceGuid.String()),
			Index: row.InterfaceIndex, Description: windows.UTF16ToString(row.Description[:]),
			Status: adapterStatus(&row), MediaType: mediaType(row.PhysicalMediumType),
			LinkSpeed: linkSpeed(row.TransmitLinkSpeed), Virtual: row.InterfaceAndOperStatusFlags&1 == 0,
			IPv4s: own,
		}
		parts := []string{}
		for _, b := range row.PhysicalAddress[:min(row.PhysicalAddressLength, uint32(len(row.PhysicalAddress)))] {
			parts = append(parts, fmt.Sprintf("%02X", b))
		}
		adapter.MAC = strings.Join(parts, "-")
		if len(own) > 0 {
			adapter.IPv4 = &own[0]
		}
		ipif := windows.MibIpInterfaceRow{Family: windows.AF_INET, InterfaceIndex: row.InterfaceIndex}
		if err := readIP(&ipif); err == nil {
			automatic := ipif.UseAutomaticMetric != 0
			adapter.Metric, adapter.AutomaticMetric = &ipif.Metric, &automatic
		} else if vanishedAdapter(err) {
			continue
		} else {
			return line, fmt.Errorf("read IPv4 interface %d: %w", row.InterfaceIndex, err)
		}
		if ssid, ok := ssids[strings.ToLower(adapter.GUID)]; ok {
			adapter.SSID = &ssid
		}
		for _, route := range defaults {
			if route.InterfaceIndex != adapter.Index {
				continue
			}
			gateway := routeIPv4(&route.NextHop)
			if adapter.RouteMetric == nil || route.Metric < *adapter.RouteMetric {
				metric := route.Metric
				adapter.Gateway, adapter.RouteMetric = &gateway, &metric
			}
		}
		line.Adapters = append(line.Adapters, adapter)
	}
	// route.exe shows the combined metric and uses "On-link" for a zero gateway.
	// Include routes on interfaces hidden from Get-NetAdapter as well.
	for _, route := range defaults {
		own := addresses[route.InterfaceIndex]
		if len(own) == 0 {
			continue
		}
		ipif := windows.MibIpInterfaceRow{Family: windows.AF_INET, InterfaceIndex: route.InterfaceIndex}
		if err := readIP(&ipif); err != nil {
			if vanishedAdapter(err) {
				continue
			}
			return line, fmt.Errorf("read route interface %d: %w", route.InterfaceIndex, err)
		}
		gateway := routeIPv4(&route.NextHop)
		if gateway == "0.0.0.0" {
			gateway = "On-link"
		}
		line.DefaultRoutes = append(line.DefaultRoutes, defaultRoute{gateway, own[0], route.Metric + ipif.Metric})
	}
	slices.SortFunc(line.Adapters, func(a, b networkAdapter) int { return strings.Compare(a.Alias, b.Alias) })
	if len(line.Adapters) == 0 {
		return line, errors.New("Windows returned no network adapters")
	}
	return line, nil
}

func network(once bool) error {
	changed := make(chan struct{}, 1)
	if !once {
		callback := windows.NewCallback(func(_, _, _ uintptr) uintptr {
			select {
			case changed <- struct{}{}:
			default:
			}
			return 0
		})
		for _, register := range []func(uint16, uintptr, unsafe.Pointer, bool, *windows.Handle) error{
			windows.NotifyIpInterfaceChange, windows.NotifyUnicastIpAddressChange, windows.NotifyRouteChange2,
		} {
			var handle windows.Handle
			if err := register(windows.AF_INET, callback, nil, false, &handle); err != nil {
				return fmt.Errorf("subscribe to network changes: %w", err)
			}
			defer windows.CancelMibChangeNotify2(handle)
		}
	}
	emit := func() error {
		line, err := readNetwork()
		if err != nil {
			return &networkReadError{err}
		}
		return writeLine(line)
	}
	if once {
		return emit()
	}
	return streamNetwork(changed, emit, 10*time.Second, 300*time.Millisecond)
}

type networkReadError struct{ error }

func streamNetwork(changed <-chan struct{}, emit func() error, refresh, coalesce time.Duration) error {
	ticker := time.NewTicker(refresh)
	defer ticker.Stop()
	var burst <-chan time.Time
	var timer *time.Timer
	var retry <-chan time.Time
	var retryTimer *time.Timer
	backoff := 500 * time.Millisecond
	read := func() error {
		err := emit()
		var failed *networkReadError
		if errors.As(err, &failed) {
			fmt.Fprintf(os.Stderr, "network read failed; retrying: %v\n", err)
			retryTimer = time.NewTimer(backoff)
			retry = retryTimer.C
			backoff = min(2*time.Second, backoff*2)
			return nil
		}
		backoff = 500 * time.Millisecond
		return err
	}
	defer func() {
		if timer != nil {
			timer.Stop()
		}
		if retryTimer != nil {
			retryTimer.Stop()
		}
	}()
	if err := read(); err != nil {
		return err
	}
	for {
		select {
		case <-changed:
			// A fixed window coalesces a burst without starving updates when
			// Windows keeps sending notifications for a busy interface.
			if burst == nil && retry == nil {
				timer = time.NewTimer(coalesce)
				burst = timer.C
			}
			continue
		case <-burst:
			burst = nil
		case <-ticker.C:
		case <-retry:
			retry = nil
		}
		if retry != nil {
			continue
		}
		if err := read(); err != nil {
			// Only output failures end the stream. Read failures never publish
			// partial data and retry without waiting for a process restart.
			return err
		}
	}
}
