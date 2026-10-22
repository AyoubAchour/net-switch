//go:build windows

package winengine

import (
	"errors"
	"fmt"
	"net/netip"
	"runtime"
	"slices"
	"sort"
	"strings"
	"unsafe"

	"github.com/AyoubAchour/net-switch/internal/wintun"
	"golang.org/x/sys/windows"
)

type Adapter struct {
	ID     string `json:"id"`
	Alias  string `json:"alias"`
	LUID   uint64 `json:"luid"`
	Index4 uint32 `json:"index4"`
	Index6 uint32 `json:"index6"`
	// Addresses are preferred: new sockets take their source from these.
	Addresses []netip.Addr `json:"addresses"`
	// Valid adds deprecated addresses, which existing flows keep using
	// (RFC 4862 5.5.4). Only an address leaving Valid closes flows.
	Valid    []netip.Addr `json:"validAddresses"`
	Up       bool         `json:"up"`
	Default4 bool         `json:"default4"`
	Default6 bool         `json:"default6"`
	MTU      uint32       `json:"mtu"`
	Metric   uint32       `json:"metric"`
}

// IP Helper copies these structures during the call. Preserve the compiler's
// pointer/escape contract across this Go wrapper too: lazy procedure lookup
// may grow the caller's stack before the native call begins.
//
//go:uintptrescapes
func api(proc string, args ...uintptr) error {
	code, _, _ := iphlp.NewProc(proc).Call(args...)
	if code != 0 {
		return fmt.Errorf("%s: %w", proc, windows.Errno(code))
	}
	return nil
}

func sockaddr(addr netip.Addr) windows.RawSockaddrInet {
	var out windows.RawSockaddrInet
	if addr.Is4() {
		p := (*windows.RawSockaddrInet4)(unsafe.Pointer(&out))
		p.Family, p.Addr = windows.AF_INET, addr.As4()
	} else {
		p := (*windows.RawSockaddrInet6)(unsafe.Pointer(&out))
		p.Family, p.Addr = windows.AF_INET6, addr.As16()
	}
	return out
}

func address(sa windows.RawSockaddrInet) netip.Addr {
	switch sa.Family {
	case windows.AF_INET:
		return netip.AddrFrom4((*windows.RawSockaddrInet4)(unsafe.Pointer(&sa)).Addr)
	case windows.AF_INET6:
		return netip.AddrFrom16((*windows.RawSockaddrInet6)(unsafe.Pointer(&sa)).Addr)
	}
	return netip.Addr{}
}

func interfaceGUID(luid uint64) (string, error) {
	var guid windows.GUID
	err := api("ConvertInterfaceLuidToGuid", uintptr(unsafe.Pointer(&luid)), uintptr(unsafe.Pointer(&guid)))
	return strings.ToUpper(guid.String()), err
}

func readAdapters() ([]Adapter, error) {
	size := uint32(32 << 10)
	var b []byte
	for attempt := 0; ; attempt++ {
		if attempt == 8 || size > 16<<20 {
			return nil, errors.New("adapter table kept growing")
		}
		b = make([]byte, size)
		err := windows.GetAdaptersAddresses(windows.AF_UNSPEC, windows.GAA_FLAG_INCLUDE_ALL_INTERFACES, 0, (*windows.IpAdapterAddresses)(unsafe.Pointer(&b[0])), &size)
		if errors.Is(err, windows.ERROR_BUFFER_OVERFLOW) {
			continue
		}
		if err != nil {
			return nil, err
		}
		break
	}
	var routes *windows.MibIpForwardTable2
	if err := windows.GetIpForwardTable2(windows.AF_UNSPEC, &routes); err != nil {
		return nil, err
	}
	defer windows.FreeMibTable(unsafe.Pointer(routes))
	default4, default6 := map[uint64]bool{}, map[uint64]bool{}
	for _, r := range routes.Rows() {
		if r.DestinationPrefix.PrefixLength == 0 {
			if r.DestinationPrefix.Prefix.Family == windows.AF_INET {
				default4[r.InterfaceLuid] = true
			}
			if r.DestinationPrefix.Prefix.Family == windows.AF_INET6 {
				default6[r.InterfaceLuid] = true
			}
		}
	}
	var result []Adapter
	for p := (*windows.IpAdapterAddresses)(unsafe.Pointer(&b[0])); p != nil; p = p.Next {
		// Virtual interfaces remain eligible. Full-tunnel VPN policy can be
		// added without changing the discovery or socket binding boundary.
		if p.IfType == 24 {
			continue
		}
		id, err := interfaceGUID(p.Luid)
		if err != nil {
			return nil, err
		}
		if strings.EqualFold(id, wintun.DefaultGUID) {
			continue
		}
		a := Adapter{ID: id, Alias: windows.UTF16PtrToString(p.FriendlyName), LUID: p.Luid,
			Index4: p.IfIndex, Index6: p.Ipv6IfIndex, Up: p.OperStatus == windows.IfOperStatusUp,
			Default4: default4[p.Luid], Default6: default6[p.Luid], MTU: p.Mtu, Metric: p.Ipv4Metric,
			Addresses: []netip.Addr{}, Valid: []netip.Addr{}}
		for u := p.FirstUnicastAddress; u != nil; u = u.Next {
			ip, ok := netip.AddrFromSlice(u.Address.IP())
			if !ok {
				continue
			}
			ip = ip.Unmap()
			if ip.IsLinkLocalUnicast() || ip.IsLoopback() {
				continue
			}
			forNew, forExisting := addressUse(u.DadState)
			if forNew {
				a.Addresses = append(a.Addresses, ip)
			}
			if forExisting {
				a.Valid = append(a.Valid, ip)
			}
		}
		result = append(result, a)
	}
	runtime.KeepAlive(b)
	sort.Slice(result, func(i, j int) bool {
		if result[i].Default4 != result[j].Default4 {
			return result[i].Default4
		}
		if result[i].Metric != result[j].Metric {
			return result[i].Metric < result[j].Metric
		}
		return result[i].ID < result[j].ID
	})
	return result, nil
}

// addressUse says what a unicast address is good for, by its duplicate
// address detection state. A preferred address serves new and existing
// connections. A deprecated one (its preferred lifetime ended, its valid
// lifetime not) keeps existing connections but starts no new ones
// (RFC 4862 5.5.4). Tentative, duplicate and invalid addresses serve neither.
// https://learn.microsoft.com/windows/win32/api/nldef/ne-nldef-nl_dad_state
func addressUse(state int32) (forNew, forExisting bool) {
	switch state {
	case windows.IpDadStatePreferred:
		return true, true
	case windows.IpDadStateDeprecated:
		return false, true
	}
	return false, false
}

// lostSources lists, per line, the addresses that left the set existing
// flows may use: the line is still up on the same interface, but the address
// is no longer valid there. A preferred address becoming deprecated is not
// lost. Lines that went down or moved are closed whole instead (lostLines).
func lostSources(old, current bindingTable) map[string][]netip.Addr {
	lost := map[string][]netip.Addr{}
	for id, previous := range old {
		now, ok := current[id]
		if !ok || !now.Up || now.LUID != previous.LUID {
			continue
		}
		for _, addr := range previous.Valid {
			if !slices.Contains(now.Valid, addr) {
				lost[id] = append(lost[id], addr)
			}
		}
	}
	return lost
}

// lostLines lists the lines whose binding is gone, down, or on another
// interface: all of their flows close.
func lostLines(old, current bindingTable) []string {
	var lines []string
	for id, previous := range old {
		if now, ok := current[id]; !ok || !now.Up || now.LUID != previous.LUID {
			lines = append(lines, id)
		}
	}
	return lines
}

// Discover includes down and virtual interfaces; usability is determined per
// address family by an actual default on that same interface.
func Discover() ([]Adapter, error) { return readAdapters() }

var localRanges = []netip.Prefix{
	netip.MustParsePrefix("10.0.0.0/8"), netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.168.0.0/16"), netip.MustParsePrefix("169.254.0.0/16"),
	netip.MustParsePrefix("224.0.0.0/4"), netip.MustParsePrefix("255.255.255.255/32"),
	netip.MustParsePrefix("fc00::/7"), netip.MustParsePrefix("fe80::/10"),
	netip.MustParsePrefix("ff00::/8"),
}

// CapturePrefixes is the exact complement of the product's LOCAL_RANGES.
// Connected host routes keep local/loopback traffic local. No physical default
// is deleted or modified.
func CapturePrefixes() []netip.Prefix {
	var out []netip.Prefix
	var visit func(netip.Prefix)
	visit = func(p netip.Prefix) {
		split := false
		for _, local := range localRanges {
			if p.Addr().Is4() != local.Addr().Is4() {
				continue
			}
			if local.Bits() <= p.Bits() && local.Contains(p.Addr()) {
				return
			}
			if p.Contains(local.Addr()) {
				split = true
			}
		}
		if !split {
			out = append(out, p)
			return
		}
		bits := p.Bits() + 1
		a := p.Addr()
		b := a.As16()
		index := p.Bits()
		if a.Is4() {
			index += 96
		}
		b[index/8] |= 1 << (7 - index%8)
		right := netip.AddrFrom16(b)
		if a.Is4() {
			right = right.Unmap()
		}
		visit(netip.PrefixFrom(a, bits))
		visit(netip.PrefixFrom(right, bits))
	}
	visit(netip.MustParsePrefix("0.0.0.0/0"))
	visit(netip.MustParsePrefix("::/0"))
	return out
}
