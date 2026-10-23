package flows

import (
	"runtime"
	"unsafe"
)

type Limits struct {
	AccountingApps, AccountingLines                                          int
	Handshakes, Flows, PerApp, UDP, UDPPerApp, Unknown, UnknownUDP, TimeWait int
	TCPBytes, PendingBytes, SnapshotBytes                                    int64
	Snapshots, SnapshotEntries                                               int
}

func Defaults() Limits {
	h := 8192
	if runtime.GOOS == "windows" {
		h = 2048
	}
	return Limits{Handshakes: h, Flows: 65536, PerApp: 8192, UDP: 16384, UDPPerApp: 4096, Unknown: 2048, UnknownUDP: 512, TimeWait: DefaultTimeWait, TCPBytes: 256 << 20, PendingBytes: 32 << 20, SnapshotBytes: 4 * (64 + 65536*(int64(unsafe.Sizeof(Record{}))+MaxOwnerBytes+128)), Snapshots: 4, SnapshotEntries: 65536}
}

// 2026-10-19, Go 1.27.2, Windows amd64: TestTimeWaitEndpointMemory's
// full-sampling heap profile measured 4,955 retained TCP bytes per endpoint;
// the whole-heap delta was 6,278 bytes including engine bookkeeping, after
// payload buffers drained (512 endpoints, two GCs). 16,384 would exceed 32 MiB.
// Reserve 8 KiB each, including headroom: 4,096 endpoints fit that budget.
// CI repeats the measurement on all four runners and keeps the heap profiles.
const DefaultTimeWait = (32 << 20) / (8 << 10)

const MinTCP = 64 << 10
const MaxOwnerBytes = 1024 + 512 + 256
