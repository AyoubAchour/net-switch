package main

import (
	"errors"
	"fmt"
	"math"
	"net/netip"
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
	value, _, err := key.GetIntegerValue("fMinimizeConnections")
	if errors.Is(err, registry.ErrNotExist) {
		return "absent", nil
	}
	if err != nil {
		return nil, err
	}
	return int32(value), nil
}

// The IP interface table includes hidden WAN miniports and Wi-Fi Direct
// devices. NCF_HIDDEN is stored by each network driver's INF; checking it
// keeps the same visible-device list as Get-NetAdapter without using WMI.
func hiddenAdapters() (map[string]bool, error) {
	result := map[string]bool{}
	class, err := registry.OpenKey(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}`, registry.ENUMERATE_SUB_KEYS)
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
			return nil, err
		}
		guid, _, guidErr := key.GetStringValue("NetCfgInstanceId")
		flags, _, flagsErr := key.GetIntegerValue("Characteristics")
		key.Close()
		if guidErr == nil && flagsErr == nil {
			result[strings.ToLower(guid)] = flags&8 != 0
		}
	}
	return result, nil
}

func routeIPv4(address *windows.RawSockaddrInet) string {
	return netip.AddrFrom4((*windows.RawSockaddrInet4)(unsafe.Pointer(address)).Addr).String()
}

func readNetwork() (networkLine, error) {
	line := networkLine{Adapters: []networkAdapter{}, DefaultRoutes: []defaultRoute{}}
	var err error
	line.Policy, err = readPolicy()
	if err != nil {
		return line, fmt.Errorf("read Wi-Fi policy: %w", err)
	}
	first, err := adapterAddresses()
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
	for _, entry := range unsafe.Slice(&table.Table[0], table.NumEntries) {
		// Get-NetAdapter lists network devices, not loopback, IP tunnels or
		// filter/endpoint interfaces stacked on top of those devices.
		if entry.Type == 24 || entry.Type == 131 || entry.InterfaceAndOperStatusFlags&0x82 != 0 || hidden[strings.ToLower(entry.InterfaceGuid.String())] {
			continue
		}
		row := windows.MibIfRow2{InterfaceIndex: entry.InterfaceIndex}
		if err := windows.GetIfEntry2Ex(windows.MibIfEntryNormal, &row); err != nil {
			return line, fmt.Errorf("read adapter %d: %w", entry.InterfaceIndex, err)
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
		if err := windows.GetIpInterfaceEntry(&ipif); err == nil {
			automatic := ipif.UseAutomaticMetric != 0
			adapter.Metric, adapter.AutomaticMetric = &ipif.Metric, &automatic
		} else if !errors.Is(err, windows.ERROR_NOT_FOUND) {
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
		if err := windows.GetIpInterfaceEntry(&ipif); err != nil {
			return line, err
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
			if err := register(windows.AF_UNSPEC, callback, nil, false, &handle); err != nil {
				return fmt.Errorf("subscribe to network changes: %w", err)
			}
			defer windows.CancelMibChangeNotify2(handle)
		}
	}
	emit := func() error {
		line, err := readNetwork()
		if err != nil {
			return err
		}
		return writeLine(line)
	}
	if once {
		return emit()
	}
	return streamNetwork(changed, emit, 30*time.Second, 300*time.Millisecond)
}

func streamNetwork(changed <-chan struct{}, emit func() error, refresh, coalesce time.Duration) error {
	if err := emit(); err != nil {
		return err
	}
	ticker := time.NewTicker(refresh)
	defer ticker.Stop()
	var burst <-chan time.Time
	var timer *time.Timer
	defer func() {
		if timer != nil {
			timer.Stop()
		}
	}()
	for {
		select {
		case <-changed:
			// A fixed window coalesces a burst without starving updates when
			// Windows keeps sending notifications for a busy interface.
			if burst == nil {
				timer = time.NewTimer(coalesce)
				burst = timer.C
			}
			continue
		case <-burst:
			burst = nil
		case <-ticker.C:
		}
		if err := emit(); err != nil {
			// Never send a partial snapshot as if adapters disappeared. Exiting
			// lets the server apply its existing helper restart backoff.
			return err
		}
	}
}
