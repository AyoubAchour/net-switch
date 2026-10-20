package winplatform

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"testing"
	"unsafe"
)

func TestStructsMatchTheWindowsLayouts(t *testing.T) {
	// Sizes and offsets of the C structs on 64-bit Windows.
	checks := []struct {
		name      string
		got, want uintptr
	}{
		{"MIB_TCPROW", unsafe.Sizeof(mibTcpRow{}), 20},
		{"TCP_ESTATS_DATA_RW_v0", unsafe.Sizeof(tcpEstatsDataRw{}), 1},
		{"TCP_ESTATS_DATA_ROD_v0", unsafe.Sizeof(tcpEstatsDataRod{}), 96},
		{"TCP_ESTATS_DATA_ROD_v0.DataBytesIn", unsafe.Offsetof(tcpEstatsDataRod{}.DataBytesIn), 16},
		{"TCP_ESTATS_DATA_ROD_v0.ThruBytesAcked", unsafe.Offsetof(tcpEstatsDataRod{}.ThruBytesAcked), 72},
		{"TCP_ESTATS_DATA_ROD_v0.ThruBytesReceived", unsafe.Offsetof(tcpEstatsDataRod{}.ThruBytesReceived), 88},
		{"MIB_TCPROW_OWNER_MODULE", unsafe.Sizeof(mibTcpRowOwnerModule{}), tcpTableRowSize},
		{"MIB_TCPROW_OWNER_MODULE.dwOwningPid", unsafe.Offsetof(mibTcpRowOwnerModule{}.OwningPid), 20},
		{"MIB_TCPROW_OWNER_MODULE.liCreateTimestamp", unsafe.Offsetof(mibTcpRowOwnerModule{}.CreateTimestamp), 24},
	}
	for _, check := range checks {
		if check.got != check.want {
			t.Errorf("%s: %d, want %d", check.name, check.got, check.want)
		}
	}
}

func TestIgnoredAddresses(t *testing.T) {
	cases := []struct {
		local, remote string
		ignored       bool
	}{
		{"192.168.1.20", "140.82.112.3", false},
		{"127.0.0.1", "140.82.112.3", true},
		{"0.0.0.0", "140.82.112.3", true},
		{"198.18.0.1", "140.82.112.3", true},
		{"198.18.0.2", "140.82.112.3", false},
		{"192.168.1.20", "10.0.0.1", true},
		{"192.168.1.20", "127.0.0.53", true},
		{"192.168.1.20", "169.254.10.1", true},
		{"192.168.1.20", "192.168.1.1", true},
		{"192.168.1.20", "172.15.0.1", false},
		{"192.168.1.20", "172.16.0.1", true},
		{"192.168.1.20", "172.31.255.255", true},
		{"192.168.1.20", "172.32.0.1", false},
		{"192.168.1.20", "224.0.0.251", true},
		{"192.168.1.20", "239.255.255.250", true},
		{"192.168.1.20", "240.0.0.1", false},
		{"192.168.1.20", "255.255.255.255", true},
		// The pattern only looks at the start of the address.
		{"192.168.1.20", "23.45.67.89", false},
		{"192.168.1.20", "1.10.0.1", false},
		{"192.168.1.20", "100.64.0.1", false},
	}
	for _, c := range cases {
		if got := ignored(c.local, c.remote); got != c.ignored {
			t.Errorf("ignored(%s, %s) = %v, want %v", c.local, c.remote, got, c.ignored)
		}
	}
}

func TestCreatedIsFormattedLikeDotNet(t *testing.T) {
	// From [DateTime]::FromFileTimeUtc($ft).ToString('o') in Windows PowerShell 5.1.
	cases := map[int64]string{
		0:                  "1601-01-01T00:00:00.0000000Z",
		116444736000000000: "1970-01-01T00:00:00.0000000Z",
		116444736000000001: "1970-01-01T00:00:00.0000001Z",
		134050418688012345: "2025-10-15T22:44:28.8012345Z",
		133999999999999999: "2025-08-18T14:13:19.9999999Z",
	}
	for filetime, want := range cases {
		if got := formatCreated(filetime); got != want {
			t.Errorf("formatCreated(%d) = %s, want %s", filetime, got, want)
		}
	}
}

func TestConnectionID(t *testing.T) {
	got := connectionID("192.168.1.20", 51234, "140.82.112.3", 443, 4321, "2025-10-15T22:44:28.8012345Z")
	want := "192.168.1.20:51234>140.82.112.3:443|4321|2025-10-15T22:44:28.8012345Z"
	if got != want {
		t.Errorf("got %s, want %s", got, want)
	}
}

// A MIB_TCPTABLE_OWNER_MODULE as Windows lays it out.
func tcpTableBytes(rows ...tcpConnection) []byte {
	table := make([]byte, tcpTableHeaderSize+len(rows)*tcpTableRowSize)
	binary.LittleEndian.PutUint32(table, uint32(len(rows)))
	for i, c := range rows {
		row := table[tcpTableHeaderSize+i*tcpTableRowSize:]
		binary.LittleEndian.PutUint32(row[0:], c.state)
		copy(row[4:8], c.local[:])
		binary.BigEndian.PutUint16(row[8:], c.localPort)
		// Windows says the upper half of a port field may hold anything.
		row[10], row[11] = 0xAB, 0xCD
		copy(row[12:16], c.remote[:])
		binary.BigEndian.PutUint16(row[16:], c.remotePort)
		row[18], row[19] = 0xEF, 0x01
		binary.LittleEndian.PutUint32(row[20:], c.pid)
		binary.LittleEndian.PutUint64(row[24:], uint64(c.created))
		row[32] = 0x77 // module info, which isn't read
	}
	return table
}

func TestTheConnectionTableIsReadInWindowsByteOrder(t *testing.T) {
	want := []tcpConnection{
		{state: 5, local: [4]byte{192, 168, 1, 20}, localPort: 51234, remote: [4]byte{140, 82, 112, 3}, remotePort: 443, pid: 4321, created: 134050418688012345},
		{state: 2, local: [4]byte{10, 0, 0, 5}, localPort: 80, remote: [4]byte{8, 8, 8, 8}, remotePort: 53, pid: 7, created: 1},
	}
	got, err := parseTcpTable(tcpTableBytes(want...))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != len(want) {
		t.Fatalf("%d rows, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("row %d: %+v, want %+v", i, got[i], want[i])
		}
	}

	// The statistics row, built like the PowerShell version's C# did:
	// BitConverter.ToUInt32(address bytes) and the port's two bytes swapped.
	row := got[0].row()
	if row.State != 5 || row.LocalAddr != 0x1401A8C0 || row.LocalPort != 0x22C8 || row.RemoteAddr != 0x0370528C || row.RemotePort != 0xBB01 {
		t.Errorf("statistics row %+v", row)
	}

	empty, err := parseTcpTable(tcpTableBytes())
	if err != nil || len(empty) != 0 {
		t.Errorf("an empty table gave %v, %v", empty, err)
	}
	table := tcpTableBytes(want...)
	if _, err := parseTcpTable(table[:len(table)-1]); err == nil {
		t.Error("a table shorter than its row count was accepted")
	}
	if _, err := parseTcpTable(table[:4]); err == nil {
		t.Error("a table without its header was accepted")
	}
}

// A stand-in for Windows, counting what the watcher asks.
type fakeTCP struct {
	connections   []tcpConnection
	failList      bool
	paths         map[uint32]string
	enableResult  uint32
	unreadable    map[uint16]bool
	bytes         map[uint16][2]uint64
	listCalls     int
	pathCalls     int
	enabledPorts  []uint16
	estatsMissing bool
}

func (f *fakeTCP) system() tcpSystem {
	return tcpSystem{
		estats: !f.estatsMissing,
		connections: func() ([]tcpConnection, error) {
			f.listCalls++
			if f.failList {
				return nil, errors.New("no table")
			}
			return f.connections, nil
		},
		processPath: func(pid uint32) string {
			f.pathCalls++
			return f.paths[pid]
		},
		enable: func(row *mibTcpRow) uint32 {
			f.enabledPorts = append(f.enabledPorts, uint16(row.LocalPort>>8|row.LocalPort<<8))
			return f.enableResult
		},
		read: func(row *mibTcpRow) (uint64, uint64, bool) {
			port := uint16(row.LocalPort>>8 | row.LocalPort<<8)
			if f.unreadable[port] {
				return 0, 0, false
			}
			b := f.bytes[port]
			return b[0], b[1], true
		},
	}
}

func established(localPort uint16, pid uint32, remote [4]byte) tcpConnection {
	return tcpConnection{state: 5, local: [4]byte{192, 168, 1, 20}, localPort: localPort, remote: remote, remotePort: 443, pid: pid, created: 134050418688012345}
}

var public = [4]byte{140, 82, 112, 3}

func TestTheWatcherFollowsThePowerShellSteps(t *testing.T) {
	fake := &fakeTCP{
		connections: []tcpConnection{
			established(1001, 10, public),
			established(1002, 10, public),
			established(1003, 20, public),                  // the engine
			established(1004, 30, [4]byte{192, 168, 1, 1}), // a device at home
			{state: 2, local: [4]byte{192, 168, 1, 20}, localPort: 1005, remote: public, remotePort: 443, pid: 10},
		},
		paths:      map[uint32]string{10: `C:\Apps\browser.exe`, 20: `C:\Program Files\Net Switch\engine\SING-BOX.exe`},
		bytes:      map[uint16][2]uint64{1001: {5000, 300}, 1002: {7, 8}},
		unreadable: map[uint16]bool{1002: true},
	}
	watcher := newOutsideWatcher(`c:\program files\net switch\engine\sing-box.exe`, fake.system())

	line := watcher.sample()
	if fake.listCalls != 1 || fake.pathCalls != 2 {
		t.Errorf("first second: %d table reads and %d path lookups, want 1 and 2 (one per owner)", fake.listCalls, fake.pathCalls)
	}
	if len(line.Outside) != 2 {
		t.Fatalf("got %d connections, want the browser's two: %+v", len(line.Outside), line.Outside)
	}
	first := line.Outside[0]
	if first.ID != "192.168.1.20:1001>140.82.112.3:443|10|2025-10-15T22:44:28.8012345Z" || first.PID != 10 ||
		first.Path != `C:\Apps\browser.exe` || first.Local != "192.168.1.20" || first.Created != "2025-10-15T22:44:28.8012345Z" {
		t.Errorf("first connection %+v", first)
	}
	if first.Down == nil || *first.Down != 5000 || first.Up == nil || *first.Up != 300 {
		t.Errorf("first connection's bytes: %v %v", first.Down, first.Up)
	}
	// Measured, but this second's read failed.
	if line.Outside[1].Down != nil || line.Outside[1].Up != nil {
		t.Error("a failed read must give null bytes")
	}
	if !line.Estats {
		t.Error("estats should be reported as available")
	}

	// Seconds two to five reuse the list; the counters are read every second.
	fake.connections = fake.connections[1:]
	fake.bytes[1001] = [2]uint64{9000, 400}
	for second := 2; second <= 5; second++ {
		line = watcher.sample()
	}
	if fake.listCalls != 1 || len(line.Outside) != 2 || *line.Outside[0].Down != 9000 {
		t.Errorf("seconds 2-5: %d table reads, %+v", fake.listCalls, line.Outside)
	}

	// The sixth second reads the list again: 1001 is gone, and the path
	// lookups start afresh.
	line = watcher.sample()
	if fake.listCalls != 2 || fake.pathCalls != 4 || len(line.Outside) != 1 || line.Outside[0].ID[:23] != "192.168.1.20:1002>140.8" {
		t.Errorf("sixth second: %d table reads, %d path lookups, %+v", fake.listCalls, fake.pathCalls, line.Outside)
	}
	// Collection is turned on once per connection.
	if len(fake.enabledPorts) != 2 || fake.enabledPorts[0] != 1001 || fake.enabledPorts[1] != 1002 {
		t.Errorf("collection turned on for %v", fake.enabledPorts)
	}

	// A table that can't be read keeps what is known.
	fake.failList = true
	for second := 7; second <= 11; second++ {
		line = watcher.sample()
	}
	if fake.listCalls != 3 || len(line.Outside) != 1 {
		t.Errorf("after a failed read: %d table reads, %+v", fake.listCalls, line.Outside)
	}
}

func TestConnectionsThatCantBeMeasuredReportNull(t *testing.T) {
	fake := &fakeTCP{connections: []tcpConnection{established(1001, 10, public)}, enableResult: 5, bytes: map[uint16][2]uint64{1001: {1, 2}}}
	line := newOutsideWatcher("", fake.system()).sample()
	if len(line.Outside) != 1 || line.Outside[0].Down != nil || line.Outside[0].Up != nil || line.Outside[0].Path != "" {
		t.Errorf("refused collection: %+v", line.Outside)
	}

	fake = &fakeTCP{connections: []tcpConnection{established(1001, 10, public)}, estatsMissing: true}
	line = newOutsideWatcher("", fake.system()).sample()
	if line.Estats || len(fake.enabledPorts) != 0 || line.Outside[0].Down != nil {
		t.Errorf("without the statistics functions: %+v, enabled %v", line, fake.enabledPorts)
	}
}

func TestOutsideLinesKeepThePowerShellShape(t *testing.T) {
	down, up := uint64(5000), uint64(300)
	line := outsideLine{Estats: true, Outside: []outsideEntry{
		{ID: "a", PID: 10, Path: `C:\x.exe`, Local: "192.168.1.20", Created: "c", Down: &down, Up: &up},
		{ID: "b", PID: 11, Local: "192.168.1.20", Created: "d"},
	}}
	got, _ := json.Marshal(line)
	want := `{"estats":true,"outside":[{"id":"a","pid":10,"path":"C:\\x.exe","local":"192.168.1.20","created":"c","down":5000,"up":300},{"id":"b","pid":11,"path":"","local":"192.168.1.20","created":"d","down":null,"up":null}]}`
	if string(got) != want {
		t.Errorf("got  %s\nwant %s", got, want)
	}
	got, _ = json.Marshal(newOutsideWatcher("", (&fakeTCP{}).system()).sample())
	if string(got) != `{"estats":true,"outside":[]}` {
		t.Errorf("no connections: %s", got)
	}
}
