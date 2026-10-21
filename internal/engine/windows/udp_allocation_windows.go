//go:build windows

package winengine

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"net"
	"net/netip"
	"os"
	"syscall"
	"time"

	"github.com/AyoubAchour/net-switch/internal/winhandle"
)

type udpAllocationFailure struct {
	At           time.Time            `json:"at"`
	Error        string               `json:"error"`
	Code         uint32               `json:"code"`
	Call         string               `json:"call"`
	Line         string               `json:"line"`
	Source       netip.Addr           `json:"source"`
	System       map[string]any       `json:"system"`
	Process      ProcessMemory        `json:"process"`
	ProcessError string               `json:"processError,omitempty"`
	NativeUDP    map[string]any       `json:"nativeUDPState"`
	Handles      any                  `json:"handleOwnership,omitempty"`
	FixedPort    fixedUDPAllocation   `json:"fixedPortProbe"`
	Reservation  *udpReservationProbe `json:"udpPortReservation"`
}

type fixedUDPAllocation struct {
	Source, Error, CloseError string
	Bound                     bool
}

func probeFixedUDPAllocation(source netip.Addr, adapter Adapter) fixedUDPAllocation {
	// Hosted diagnosis only: a separate, empty socket tests whether resources
	// still permit an explicit port after automatic allocation failed. This
	// never retries or forwards the refused flow and preserves both bindings.
	result := fixedUDPAllocation{Source: netip.AddrPortFrom(source, 28000).String()}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	network := "udp4"
	if source.Is6() {
		network = "udp6"
	}
	config := net.ListenConfig{Control: bindSocket(adapter, source.Is6())}
	conn, err := config.ListenPacket(ctx, network, result.Source)
	if err != nil {
		result.Error = err.Error()
		return result
	}
	result.Bound = true
	owner, err := ownGoDescriptor(conn.(*net.UDPConn), "hosted fixed-port resource probe")
	if err == nil {
		err = owner.CloseGo("hosted fixed-port resource probe close", conn.Close)
	} else {
		err = errors.Join(err, conn.Close())
	}
	if err != nil {
		result.CloseError = err.Error()
	}
	return result
}

func (d *Dialer) captureUDPAllocationFailure(line string, source netip.Addr, adapter Adapter, err error) {
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
	// Other refusals do not wait for it; the refused flow is never retried.
	// The separate fixed-port diagnostic below sends no traffic.
	space := captureUDPPortSpace()
	snapshot.NativeUDP, snapshot.Reservation = space.Native, space.Probe
	snapshot.System = systemResources()
	var memoryError error
	snapshot.Process, memoryError = processMemory()
	if memoryError != nil {
		snapshot.ProcessError = memoryError.Error()
	}
	snapshot.Handles = winhandle.Stats()
	snapshot.FixedPort = probeFixedUDPAllocation(source, adapter)
	d.udpFailure.Store(snapshot)
	// The exact errno and call remain visible even if a later large stats
	// response is unavailable. The complete census is kept in stats/artifacts.
	value, _ := json.Marshal(map[string]any{"at": snapshot.At, "call": snapshot.Call, "code": snapshot.Code,
		"line": line, "source": source, "error": err.Error(), "system": snapshot.System,
		"process": snapshot.Process, "processError": snapshot.ProcessError,
		"nativeUniquePorts": snapshot.NativeUDP["uniquePorts"], "handleOwnership": snapshot.Handles,
		"fixedPortProbe": snapshot.FixedPort})
	log.Printf("WINDOWS UDP ALLOCATION FAILURE %s", value)
	// Port settings are read in the background against the table captured
	// above; the result is logged and replaces "pending" in stats.
	d.reservations.start(space, runNetsh)
}
