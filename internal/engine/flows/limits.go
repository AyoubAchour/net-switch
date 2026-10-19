package flows

import (
	"runtime"
	"unsafe"
)

type Limits struct {
	Handshakes, Flows, PerApp, UDP, UDPPerApp, Unknown, UnknownUDP, TimeWait int
	TCPBytes, PendingBytes, SnapshotBytes                                    int64
	Snapshots, SnapshotEntries                                               int
}

func Defaults() Limits {
	h := 8192
	if runtime.GOOS == "windows" {
		h = 2048
	}
	return Limits{Handshakes: h, Flows: 65536, PerApp: 8192, UDP: 16384, UDPPerApp: 4096, Unknown: 2048, UnknownUDP: 512, TimeWait: 65536, TCPBytes: 256 << 20, PendingBytes: 32 << 20, SnapshotBytes: 4 * (64 + 65536*(int64(unsafe.Sizeof(Record{}))+MaxOwnerBytes+128)), Snapshots: 4, SnapshotEntries: 65536}
}

const MinTCP = 64 << 10
const MaxOwnerBytes = 1024 + 512 + 256
