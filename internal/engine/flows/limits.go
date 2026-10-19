package flows

import "runtime"

type Limits struct {
	Handshakes, Flows, PerApp, UDP, UDPPerApp, Unknown, UnknownUDP int
	TCPBytes, PendingBytes, SnapshotBytes                          int64
	Snapshots, SnapshotEntries                                     int
}

func Defaults() Limits {
	h := 8192
	if runtime.GOOS == "windows" {
		h = 2048
	}
	return Limits{Handshakes: h, Flows: 65536, PerApp: 8192, UDP: 16384, UDPPerApp: 4096, Unknown: 2048, UnknownUDP: 512, TCPBytes: 256 << 20, PendingBytes: 32 << 20, SnapshotBytes: 16 << 20, Snapshots: 4, SnapshotEntries: 65536}
}

const MinTCP = 2*(64<<10) + 2*(32<<10)
const DefaultTCP = 2*(1<<20) + 2*(32<<10)
