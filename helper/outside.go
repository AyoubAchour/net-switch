package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math/bits"
	"net/netip"
	"os"
	"regexp"
	"slices"
	"strings"
	"time"
)

// Connections that go around the routing engine, with their byte counts from
// Windows' per-connection statistics (Get/SetPerTcpConnectionEStats), which
// need administrator rights. This is the PowerShell version's logic, step by
// step: the connection list is read every fifth second, and the counters of
// the connections found are read every second.

type outsideEntry struct {
	ID      string  `json:"id"`
	PID     uint32  `json:"pid"`
	Path    string  `json:"path"`
	Local   string  `json:"local"`
	Created string  `json:"created"`
	Down    *uint64 `json:"down"`
	Up      *uint64 `json:"up"`
}

type outsideLine struct {
	Estats  bool           `json:"estats"`
	Outside []outsideEntry `json:"outside"`
}

// The connection list is read this often, in seconds.
const rescanEvery = 5

// Local addresses that aren't on either line: loopback, unbound, and the
// routing engine's own tunnel.
var skipLocal = map[string]bool{"127.0.0.1": true, "0.0.0.0": true, "198.18.0.1": true}

// Remote addresses on a local network, loopback, link-local, multicast and
// broadcast. The same pattern the PowerShell version matched.
var privateRemote = regexp.MustCompile(`^(10\.|127\.|169\.254\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.|22[4-9]\.|23[0-9]\.|255\.)`)

func ignored(local, remote string) bool {
	return skipLocal[local] || privateRemote.MatchString(remote)
}

// One row of the connection table.
type tcpConnection struct {
	state      uint32
	local      [4]byte
	localPort  uint16
	remote     [4]byte
	remotePort uint16
	pid        uint32
	// A FILETIME: 100 ns steps since 1601-01-01 UTC.
	created int64
}

// The row Windows' statistics calls take: the PowerShell version built it the
// same way, with the addresses and ports in network byte order.
func (c tcpConnection) row() mibTcpRow {
	return mibTcpRow{
		State:      tcpStateEstablished,
		LocalAddr:  binary.LittleEndian.Uint32(c.local[:]),
		LocalPort:  uint32(bits.ReverseBytes16(c.localPort)),
		RemoteAddr: binary.LittleEndian.Uint32(c.remote[:]),
		RemotePort: uint32(bits.ReverseBytes16(c.remotePort)),
	}
}

// Like .NET's DateTime.ToString("o") for a UTC time, which the PowerShell
// version used: seven fractional digits and a Z.
func formatCreated(filetime int64) string {
	const ticksPerSecond = 10_000_000
	// Seconds from 1601-01-01 to 1970-01-01.
	const unixEpoch = 11_644_473_600
	t := time.Unix(filetime/ticksPerSecond-unixEpoch, filetime%ticksPerSecond*100).UTC()
	return t.Format("2006-01-02T15:04:05.0000000") + "Z"
}

// The owner and start time are part of the id too, so a reused address and
// port is never mistaken for the old connection.
func connectionID(local string, localPort uint16, remote string, remotePort uint16, pid uint32, created string) string {
	return fmt.Sprintf("%s:%d>%s:%d|%d|%s", local, localPort, remote, remotePort, pid, created)
}

// What the watcher asks Windows. Tests replace it.
type tcpSystem struct {
	estats      bool
	connections func() ([]tcpConnection, error)
	processPath func(pid uint32) string
	// Returns Windows' result code: 0 means collection is on.
	enable func(row *mibTcpRow) uint32
	read   func(row *mibTcpRow) (down, up uint64, ok bool)
}

type trackedConnection struct {
	entry    outsideEntry
	row      mibTcpRow
	measured bool
}

type outsideWatcher struct {
	engine  string
	system  tcpSystem
	tick    int
	tracked map[string]*trackedConnection
}

func newOutsideWatcher(engine string, system tcpSystem) *outsideWatcher {
	return &outsideWatcher{engine: engine, system: system, tracked: map[string]*trackedConnection{}}
}

func (w *outsideWatcher) sample() outsideLine {
	if w.tick%rescanEvery == 0 {
		w.rescan()
	}
	w.tick++
	line := outsideLine{Estats: w.system.estats, Outside: make([]outsideEntry, 0, len(w.tracked))}
	ids := make([]string, 0, len(w.tracked))
	for id := range w.tracked {
		ids = append(ids, id)
	}
	slices.Sort(ids)
	for _, id := range ids {
		tracked := w.tracked[id]
		entry := tracked.entry
		if tracked.measured {
			if down, up, ok := w.system.read(&tracked.row); ok {
				entry.Down, entry.Up = &down, &up
			}
		}
		line.Outside = append(line.Outside, entry)
	}
	return line
}

func (w *outsideWatcher) rescan() {
	connections, err := w.system.connections()
	if err != nil {
		// A failed read doesn't mean the connections closed: keep them.
		fmt.Fprintf(os.Stderr, "can't read the connection table: %v\n", err)
		return
	}
	paths := map[uint32]string{}
	seen := map[string]bool{}
	for _, c := range connections {
		if c.state != tcpStateEstablished {
			continue
		}
		local, remote := netip.AddrFrom4(c.local).String(), netip.AddrFrom4(c.remote).String()
		if ignored(local, remote) {
			continue
		}
		path, known := paths[c.pid]
		if !known {
			path = w.system.processPath(c.pid)
			paths[c.pid] = path
		}
		// The engine's own connections are the routed traffic itself. Windows
		// paths ignore case, as PowerShell's -eq did.
		if w.engine != "" && strings.EqualFold(path, w.engine) {
			continue
		}
		created := formatCreated(c.created)
		id := connectionID(local, c.localPort, remote, c.remotePort, c.pid, created)
		seen[id] = true
		if w.tracked[id] != nil {
			continue
		}
		row := c.row()
		measured := w.system.estats && w.system.enable(&row) == 0
		w.tracked[id] = &trackedConnection{
			entry:    outsideEntry{ID: id, PID: c.pid, Path: path, Local: local, Created: created},
			row:      row,
			measured: measured,
		}
	}
	for id := range w.tracked {
		if !seen[id] {
			delete(w.tracked, id)
		}
	}
}

const (
	afInet = 2
	// Connected rows only, with the owning process and creation time.
	tcpTableOwnerModuleConnections = 7
	tcpStateEstablished            = 5
	tcpConnectionEstatsData        = 1
)

// MIB_TCPROW.
type mibTcpRow struct {
	State      uint32
	LocalAddr  uint32
	LocalPort  uint32
	RemoteAddr uint32
	RemotePort uint32
}

// TCP_ESTATS_DATA_RW_v0.
type tcpEstatsDataRw struct {
	EnableCollection byte
}

// TCP_ESTATS_DATA_ROD_v0.
type tcpEstatsDataRod struct {
	DataBytesOut      uint64
	DataSegsOut       uint64
	DataBytesIn       uint64
	DataSegsIn        uint64
	SegsOut           uint64
	SegsIn            uint64
	SoftErrors        uint32
	SoftErrorReason   uint32
	SndUna            uint32
	SndNxt            uint32
	SndMax            uint32
	ThruBytesAcked    uint64
	RcvNxt            uint32
	ThruBytesReceived uint64
}

// MIB_TCPROW_OWNER_MODULE. The table is read byte by byte at these offsets
// (see parseTcpTable); the struct is here so the tests can check them.
type mibTcpRowOwnerModule struct {
	State            uint32
	LocalAddr        uint32
	LocalPort        uint32
	RemoteAddr       uint32
	RemotePort       uint32
	OwningPid        uint32
	CreateTimestamp  int64
	OwningModuleInfo [16]uint64
}

const (
	// MIB_TCPTABLE_OWNER_MODULE: the row count, then padding that puts the
	// rows on an 8-byte boundary.
	tcpTableHeaderSize = 8
	tcpTableRowSize    = 160
)

// Reads a MIB_TCPTABLE_OWNER_MODULE. Addresses are stored as their four bytes
// in order; ports in network byte order in the low 16 bits (Windows says the
// upper 16 bits may hold anything).
func parseTcpTable(table []byte) ([]tcpConnection, error) {
	if len(table) < tcpTableHeaderSize {
		return nil, errors.New("the connection table is cut short")
	}
	count := binary.LittleEndian.Uint32(table)
	if uint64(count) > uint64(len(table)-tcpTableHeaderSize)/tcpTableRowSize {
		return nil, fmt.Errorf("the connection table says %d rows but holds %d bytes", count, len(table))
	}
	connections := make([]tcpConnection, count)
	for i := range connections {
		row := table[tcpTableHeaderSize+i*tcpTableRowSize:]
		connections[i] = tcpConnection{
			state:      binary.LittleEndian.Uint32(row[0:]),
			local:      [4]byte(row[4:8]),
			localPort:  binary.BigEndian.Uint16(row[8:]),
			remote:     [4]byte(row[12:16]),
			remotePort: binary.BigEndian.Uint16(row[16:]),
			pid:        binary.LittleEndian.Uint32(row[20:]),
			created:    int64(binary.LittleEndian.Uint64(row[24:])),
		}
	}
	return connections, nil
}
