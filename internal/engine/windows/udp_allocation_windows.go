//go:build windows

package winengine

import (
	"encoding/json"
	"errors"
	"log"
	"net/netip"
	"os"
	"syscall"
	"time"

	"github.com/AyoubAchour/net-switch/internal/winhandle"
)

type udpAllocationFailure struct {
	At           time.Time      `json:"at"`
	Error        string         `json:"error"`
	Code         uint32         `json:"code"`
	Call         string         `json:"call"`
	Line         string         `json:"line"`
	Source       netip.Addr     `json:"source"`
	System       map[string]any `json:"system"`
	Process      ProcessMemory  `json:"process"`
	ProcessError string         `json:"processError,omitempty"`
	NativeUDP    map[string]any `json:"nativeUDPState"`
	Handles      any            `json:"handleOwnership,omitempty"`
}

func (d *Dialer) captureUDPAllocationFailure(line string, source netip.Addr, err error) {
	if !hostedTraceEnabled() || !d.udpFailureStarted.CompareAndSwap(false, true) {
		return
	}
	snapshot := &udpAllocationFailure{At: time.Now(), Error: err.Error(), Line: line, Source: source}
	var code syscall.Errno
	if errors.As(err, &code) {
		snapshot.Code = uint32(code)
	}
	var call *os.SyscallError
	if errors.As(err, &call) {
		snapshot.Call = call.Syscall
	}
	// Only the first failing allocation takes these read-only snapshots.
	// Other refusals do not wait for it; there is no bind retry or new socket.
	snapshot.NativeUDP = nativeUDPState()
	snapshot.System = systemResources()
	var memoryError error
	snapshot.Process, memoryError = processMemory()
	if memoryError != nil {
		snapshot.ProcessError = memoryError.Error()
	}
	snapshot.Handles = winhandle.Stats()
	d.udpFailure.Store(snapshot)
	// The exact errno and call remain visible even if a later large stats
	// response is unavailable. The complete census is kept in stats/artifacts.
	value, _ := json.Marshal(map[string]any{"at": snapshot.At, "call": snapshot.Call, "code": snapshot.Code,
		"line": line, "source": source, "error": err.Error(), "system": snapshot.System,
		"process": snapshot.Process, "processError": snapshot.ProcessError,
		"nativeUniquePorts": snapshot.NativeUDP["uniquePorts"], "handleOwnership": snapshot.Handles})
	log.Printf("WINDOWS UDP ALLOCATION FAILURE %s", value)
}
