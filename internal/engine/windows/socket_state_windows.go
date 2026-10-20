//go:build windows

package winengine

import (
	"context"
	"encoding/binary"
	"net/netip"
	"os"
	"slices"
	"unsafe"

	"golang.org/x/sys/windows"
)

type tcpStateGroup struct {
	Source      string   `json:"source"`
	Destination string   `json:"destination"`
	RemotePort  uint16   `json:"remotePort"`
	PID         uint32   `json:"pid"`
	State       uint32   `json:"state"`
	Ports       []uint16 `json:"ports"`
}

// Hosted diagnostics, using the same native owner-table helper as lookup.
// TIME_WAIT rows remain visible when Windows clears their owning PID.
// A table-derived free count is evidence, not a promise that a racing bind
// will succeed: the OS can reserve ports which do not appear in this table.
func nativeSocketState() map[string]any {
	result := map[string]any{"pid": os.Getpid()}
	type key struct {
		source, destination netip.Addr
		remote              uint16
		pid, state          uint32
	}
	groups := map[key][]uint16{}
	used := map[uint16]bool{}
	for _, family := range []uint32{windows.AF_INET, windows.AF_INET6} {
		b, err := readOwnerTable(context.Background(), tcpTable, family, tcpOwnerPIDAll)
		if err != nil {
			return map[string]any{"error": err.Error()}
		}
		stride := 24
		if family == windows.AF_INET6 {
			stride = 56
		}
		rows, err := ownerRows(b, 4, stride)
		if err != nil {
			return map[string]any{"error": err.Error()}
		}
		for _, row := range rows {
			var k key
			var port uint16
			if family == windows.AF_INET {
				k.source, k.destination = netip.AddrFrom4([4]byte(row[4:8])), netip.AddrFrom4([4]byte(row[12:16]))
				port, k.remote = binary.BigEndian.Uint16(row[8:]), binary.BigEndian.Uint16(row[16:])
				k.pid, k.state = binary.LittleEndian.Uint32(row[20:]), binary.LittleEndian.Uint32(row)
			} else {
				k.source, k.destination = netip.AddrFrom16([16]byte(row[:16])), netip.AddrFrom16([16]byte(row[24:40]))
				port, k.remote = binary.BigEndian.Uint16(row[20:]), binary.BigEndian.Uint16(row[44:])
				k.pid, k.state = binary.LittleEndian.Uint32(row[52:]), binary.LittleEndian.Uint32(row[48:])
			}
			used[port] = true
			// Include other processes too: a port freed by our fixture can be
			// reused by Windows before the native bindability probe reaches it.
			groups[k] = append(groups[k], port)
		}
	}
	var rows []tcpStateGroup
	for k, ports := range groups {
		slices.Sort(ports)
		rows = append(rows, tcpStateGroup{k.source.String(), k.destination.String(), k.remote, k.pid, k.state, ports})
	}
	ports := make([]uint16, 0, len(used))
	for port := range used {
		ports = append(ports, port)
	}
	slices.Sort(ports)
	result["groups"], result["usedLocalPorts"] = rows, ports
	var count uint32
	ok, _, err := windows.NewLazySystemDLL("kernel32.dll").NewProc("GetProcessHandleCount").Call(
		uintptr(windows.CurrentProcess()), uintptr(unsafe.Pointer(&count)))
	if ok == 0 {
		result["handleError"] = err.Error()
	} else {
		result["handles"] = count
	}
	return result
}

// UDP has no TIME_WAIT rows. Count live native bindings by process/source so a
// failed bind can be compared with the same runner's actual port occupancy.
func nativeUDPState() map[string]any {
	type key struct {
		source netip.Addr
		pid    uint32
	}
	type group struct {
		Source string   `json:"source"`
		PID    uint32   `json:"pid"`
		Ports  []uint16 `json:"ports"`
	}
	grouped := map[key][]uint16{}
	used := map[uint16]bool{}
	var count [2]int
	for family, af := range []uint32{windows.AF_INET, windows.AF_INET6} {
		raw, err := readOwnerTable(context.Background(), udpTable, af, 1) // UDP_TABLE_OWNER_PID.
		if err != nil {
			return map[string]any{"error": err.Error()}
		}
		stride := 12
		if family == 1 {
			stride = 28
		}
		rows, err := ownerRows(raw, 4, stride)
		if err != nil {
			return map[string]any{"error": err.Error()}
		}
		count[family] = len(rows)
		for _, row := range rows {
			var value key
			var port uint16
			if family == 0 {
				value.source = netip.AddrFrom4([4]byte(row[:4]))
				port, value.pid = binary.BigEndian.Uint16(row[4:]), binary.LittleEndian.Uint32(row[8:])
			} else {
				value.source = netip.AddrFrom16([16]byte(row[:16]))
				port, value.pid = binary.BigEndian.Uint16(row[20:]), binary.LittleEndian.Uint32(row[24:])
			}
			grouped[value] = append(grouped[value], port)
			used[port] = true
		}
	}
	var groups []group
	for value, ports := range grouped {
		slices.Sort(ports)
		groups = append(groups, group{value.source.String(), value.pid, ports})
	}
	ports := make([]uint16, 0, len(used))
	for port := range used {
		ports = append(ports, port)
	}
	slices.Sort(ports)
	return map[string]any{"rowsByFamily": count, "groups": groups, "usedLocalPorts": ports, "uniquePorts": len(ports)}
}
