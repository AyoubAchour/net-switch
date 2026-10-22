package lifecycle_test

import (
	"encoding/json"
	"fmt"
	"net"
	"testing"
	"time"
	"unsafe"

	"github.com/AyoubAchour/net-switch/internal/winclock"
	"golang.org/x/sys/windows"
)

// TCP_INFO_v0's documented Windows ABI, independent of the engine. The
// synchronous query reads client-side TCP state; it changes no socket options.
// https://learn.microsoft.com/windows/win32/api/mstcpip/ns-mstcpip-tcp_info_v0
type nativeTCPInfo struct {
	State, MSS                                                                          uint32
	ConnectionMS                                                                        uint64
	Timestamps                                                                          uint8
	_                                                                                   [3]byte
	RTTUs, MinRTTUs, BytesInFlight, Cwnd, SendWindow, ReceiveWindow, ReceiveBuffer      uint32
	BytesOut, BytesIn                                                                   uint64
	BytesReordered, BytesRetransmitted, FastRetransmits, DuplicateACKs, TimeoutEpisodes uint32
	SYNRetransmits                                                                      uint8
	_                                                                                   [3]byte
}

func readNativeTCPInfo(conn *net.TCPConn) (nativeTCPInfo, error) {
	var info nativeTCPInfo
	raw, err := conn.SyscallConn()
	if err != nil {
		return info, err
	}
	var queryErr error
	err = raw.Control(func(fd uintptr) {
		var version, returned uint32
		queryErr = windows.WSAIoctl(windows.Handle(fd), windows.IOC_INOUT|windows.IOC_VENDOR|39,
			(*byte)(unsafe.Pointer(&version)), 4, (*byte)(unsafe.Pointer(&info)), uint32(unsafe.Sizeof(info)), &returned, nil, 0)
		if queryErr == nil && returned != uint32(unsafe.Sizeof(info)) {
			queryErr = fmt.Errorf("TCP_INFO_v0 returned %d bytes", returned)
		}
	})
	if err != nil {
		return info, err
	}
	return info, queryErr
}

func nativeSocketObserver(t *testing.T, conn net.Conn) func(string) {
	t.Helper()
	tcp, ok := conn.(*net.TCPConn)
	if !ok {
		t.Fatalf("native socket observer needs the real TCP client, got %T", conn)
	}
	// Measure this diagnostic before arming a fault. It runs at most once per
	// second afterwards, never per packet, and does not query/clear SO_ERROR.
	var total, longest time.Duration
	var last nativeTCPInfo
	for range 16 {
		start := winclock.Now()
		info, err := readNativeTCPInfo(tcp)
		elapsed := winclock.Since(start)
		if err != nil {
			t.Fatal("TCP client precondition", err)
		}
		total += elapsed
		longest = max(longest, elapsed)
		last = info
	}
	if last.State != 4 {
		t.Fatal("held TCP client is not established", last)
	}
	t.Logf("M4_TCP_PROBE samples=16 total=%s slowest=%s interval=5s socket=%s->%s", total, longest, tcp.LocalAddr(), tcp.RemoteAddr())
	if total > 100*time.Millisecond {
		t.Fatal("TCP observer is too expensive for the stall measurement", total)
	}
	options := map[string]any{}
	raw, err := tcp.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	if err := raw.Control(func(fd uintptr) {
		for _, opt := range []struct {
			name          string
			level, option int
		}{
			{"keepalive", windows.SOL_SOCKET, windows.SO_KEEPALIVE},
			{"receive_timeout_ms", windows.SOL_SOCKET, windows.SO_RCVTIMEO},
			{"send_timeout_ms", windows.SOL_SOCKET, windows.SO_SNDTIMEO},
			{"keep_idle_seconds", windows.IPPROTO_TCP, windows.TCP_KEEPIDLE},
			{"keep_interval_seconds", windows.IPPROTO_TCP, windows.TCP_KEEPINTVL},
			{"keep_count", windows.IPPROTO_TCP, windows.TCP_KEEPCNT},
			{"max_retransmit_seconds", windows.IPPROTO_TCP, windows.TCP_MAXRT},
			{"max_retransmit_ms", windows.IPPROTO_TCP, windows.TCP_MAXRTMS},
		} {
			value, err := windows.GetsockoptInt(windows.Handle(fd), opt.level, opt.option)
			if err != nil {
				options[opt.name] = err.Error()
			} else {
				options[opt.name] = value
			}
		}
	}); err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(options)
	t.Logf("M4_TCP_OPTIONS unchanged=true values=%s", b)
	started, lastGood := winclock.Now(), winclock.Now()
	return func(phase string) {
		start := winclock.Now()
		info, err := readNativeTCPInfo(tcp)
		if err == nil {
			last, lastGood = info, winclock.Now()
		}
		b, _ := json.Marshal(last)
		t.Logf("M4_TCP phase=%s since_baseline=%s sample_cost=%s last_success_age=%s info=%s error=%v", phase, winclock.Since(started), winclock.Since(start), winclock.Since(lastGood), b, err)
	}
}

func TestNativeTCPInfoLayout(t *testing.T) {
	var v nativeTCPInfo
	if unsafe.Sizeof(v) != 88 || unsafe.Offsetof(v.RTTUs) != 20 || unsafe.Offsetof(v.BytesOut) != 48 || unsafe.Offsetof(v.TimeoutEpisodes) != 80 {
		t.Fatal("TCP_INFO_v0 ABI differs", unsafe.Sizeof(v), unsafe.Offsetof(v.RTTUs), unsafe.Offsetof(v.BytesOut), unsafe.Offsetof(v.TimeoutEpisodes))
	}
}
