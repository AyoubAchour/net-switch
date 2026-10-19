package winplatform

import (
	"errors"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	iphlpapi                      = windows.NewLazySystemDLL("iphlpapi.dll")
	procGetExtendedTcpTable       = iphlpapi.NewProc("GetExtendedTcpTable")
	procSetPerTcpConnectionEStats = iphlpapi.NewProc("SetPerTcpConnectionEStats")
	procGetPerTcpConnectionEStats = iphlpapi.NewProc("GetPerTcpConnectionEStats")
)

func windowsTCP() tcpSystem {
	return tcpSystem{
		estats:      procSetPerTcpConnectionEStats.Find() == nil && procGetPerTcpConnectionEStats.Find() == nil,
		connections: tcpConnections,
		processPath: processPath,
		enable:      enableEstats,
		read:        readEstats,
	}
}

// Kept between reads; it grows when the table doesn't fit.
var tcpTableBuffer = make([]byte, 64*1024)

// The IPv4 TCP connections, with their owner and creation time.
func tcpConnections() ([]tcpConnection, error) {
	return tcpTable(tcpTableOwnerModuleConnections)
}

func tcpTable(class uintptr) ([]tcpConnection, error) {
	for attempt := 0; attempt < 5; attempt++ {
		size := uint32(len(tcpTableBuffer))
		result, _, _ := procGetExtendedTcpTable.Call(
			uintptr(unsafe.Pointer(&tcpTableBuffer[0])), uintptr(unsafe.Pointer(&size)),
			0, afInet, class, 0)
		switch windows.Errno(result) {
		case 0:
			return parseTcpTable(tcpTableBuffer)
		case windows.ERROR_INSUFFICIENT_BUFFER:
			// Connections can open before the next try: leave some room.
			tcpTableBuffer = make([]byte, size+size/4)
		default:
			return nil, windows.Errno(result)
		}
	}
	return nil, errors.New("the connection table kept growing")
}

// Kept between calls; it grows for a path that doesn't fit.
var pathBuffer = make([]uint16, 1024)

// The program a process runs, or "" when Windows won't say (the System
// process, or one that has already ended), as PowerShell's Path gave "".
func processPath(pid uint32) string {
	process, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return ""
	}
	defer windows.CloseHandle(process)
	for {
		size := uint32(len(pathBuffer))
		err := windows.QueryFullProcessImageName(process, 0, &pathBuffer[0], &size)
		if err == nil {
			return windows.UTF16ToString(pathBuffer[:size])
		}
		if !errors.Is(err, windows.ERROR_INSUFFICIENT_BUFFER) || len(pathBuffer) >= windows.MAX_LONG_PATH {
			return ""
		}
		pathBuffer = make([]uint16, windows.MAX_LONG_PATH)
	}
}

func enableEstats(row *mibTcpRow) uint32 {
	rw := tcpEstatsDataRw{EnableCollection: 1}
	result, _, _ := procSetPerTcpConnectionEStats.Call(
		uintptr(unsafe.Pointer(row)), tcpConnectionEstatsData,
		uintptr(unsafe.Pointer(&rw)), 0, unsafe.Sizeof(rw), 0)
	return uint32(result)
}

// Windows documents the counters as meaningless unless EnableCollection comes
// back set, so anything else counts as "not measured".
func readEstats(row *mibTcpRow) (down, up uint64, ok bool) {
	var rw tcpEstatsDataRw
	var rod tcpEstatsDataRod
	result, _, _ := procGetPerTcpConnectionEStats.Call(
		uintptr(unsafe.Pointer(row)), tcpConnectionEstatsData,
		uintptr(unsafe.Pointer(&rw)), 0, unsafe.Sizeof(rw),
		0, 0, 0,
		uintptr(unsafe.Pointer(&rod)), 0, unsafe.Sizeof(rod))
	if result != 0 || rw.EnableCollection != 1 {
		return 0, 0, false
	}
	return rod.DataBytesIn, rod.DataBytesOut, true
}
