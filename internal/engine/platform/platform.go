// Package platform defines the OS boundary. Implementations must honor context
// cancellation and never retry an egress socket without its line binding.
package platform

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"time"
)

var ErrNotYet = errors.New("platform support not yet implemented")
var ErrAmbiguous = errors.New("socket has ambiguous owners")

type TunDevice interface {
	ReadPacket(context.Context, []byte) (int, error)
	WritePacket(context.Context, []byte) error
	MTU() int
	Close() error
}

type Tuple struct {
	Source      netip.AddrPort `json:"source"`
	Destination netip.AddrPort `json:"destination"`
}

type Owner struct {
	PID        uint32 `json:"pid"`
	StartTime  uint64 `json:"startTime"`
	Path       string `json:"path"`
	AppID      string `json:"id"`
	Generation string `json:"socketGeneration"`
}

type OwnerLookup interface {
	TCP(context.Context, Tuple) (Owner, error)
	UDP(context.Context, netip.AddrPort) (Owner, error)
}

// A complete snapshot includes every requested endpoint, including absence.
// On an incomplete dump return an error; never mark it as a fresh validation.
type UDPIdentity interface {
	Snapshot(context.Context, []netip.AddrPort) (map[netip.AddrPort]Owner, error)
}

type TCPConn interface {
	net.Conn
	CloseRead() error
	CloseWrite() error
}

type UDPConn interface {
	ReadFrom([]byte) (int, netip.AddrPort, error)
	WriteTo([]byte, netip.AddrPort, bool) (int, error)
	LocalAddr() netip.AddrPort
	Close() error
}

// TooBig carries the path MTU from a synchronous write or an OS error queue.
type TooBig struct{ MTU uint32 }

func (e *TooBig) Error() string { return "datagram exceeds path MTU" }

type DatagramError struct {
	Destination netip.AddrPort
	Payload     []byte
	MTU         uint32
	Unreachable bool
}

type UDPErrorQueue interface {
	ReadError(context.Context) (DatagramError, error)
}

type LineDialer interface {
	DialTCP(context.Context, string, netip.AddrPort) (TCPConn, error)
	OpenUDP(context.Context, string, bool) (UDPConn, error)
}

// Prepare must use the ownership journal. Capture is enabled only after all
// policy and routes are ready. Cleanup is idempotent and fingerprint checked.
type RouteManager interface {
	Prepare(context.Context, []Line) error
	Capture(context.Context) error
	Cleanup(context.Context) error
}

type Line struct {
	ID        string       `json:"id"`
	Addresses []netip.Addr `json:"addresses"`
}

type ProbeResult struct {
	OK      bool          `json:"ok"`
	Latency time.Duration `json:"latency"`
	Error   string        `json:"error,omitempty"`
}

type Prober interface {
	Probe(context.Context, string, string) (ProbeResult, error)
}
