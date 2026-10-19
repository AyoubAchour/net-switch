// Package platform defines the OS boundary. Implementations must honor context
// cancellation and never retry an egress socket without its line binding.
package platform

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"syscall"
	"time"
)

var ErrNotYet = errors.New("platform support not yet implemented")
var ErrAmbiguous = errors.New("socket has ambiguous owners")

type TunDevice interface {
	// One ordered reader only. Linux devices must not use IFF_MULTI_QUEUE;
	// implementations splitting GSO batches preserve their wire order.
	ReadPacket(context.Context, []byte) (int, error)
	WritePacket(context.Context, []byte) error
	MTU() int
	Close() error
}

// BatchWriter accepts packets already available in the link queue, without
// waiting to fill a batch. The return count excludes packets dropped under load.
type BatchWriter interface {
	WriteBatch([][]byte) (int, error)
}

// ChecksumVerifier describes only packets returned by this device's reader.
// Fragments and protocols it did not verify must return false.
type ChecksumVerifier interface {
	RXChecksumVerified([]byte) bool
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

// DatagramOwnerLookup supplies the first remote endpoint for Linux's exact
// sock_diag query. Source-only lookup remains available for other adapters.
type DatagramOwnerLookup interface {
	UDPFor(context.Context, Tuple) (Owner, error)
}

// A complete snapshot includes every requested endpoint, including absence.
// On an incomplete dump return an error; never mark it as a fresh validation.
type UDPIdentity interface {
	Snapshot(context.Context, []netip.AddrPort) (map[netip.AddrPort]Owner, error)
}

// UDPIdentityAt supplies the beginning of session enumeration, so a cache
// can retain lookups that completed after that list was collected. The list
// includes pending sessions; only ready sessions consume its validation.
type UDPIdentityAt interface {
	SnapshotAt(context.Context, []netip.AddrPort, time.Time) (map[netip.AddrPort]Owner, error)
}

type TCPConn interface {
	net.Conn
	CloseRead() error
	CloseWrite() error
	// SetLinger(0) followed by Close aborts the remote connection with RST.
	SetLinger(int) error
}

// ReadFrom errors describe individual datagrams unless errors.Is(net.ErrClosed).
// Translate EMSGSIZE/WSAEMSGSIZE to TooBig; other receive errors remain
// recoverable. Close unblocks ReadFrom. The NAT keeps the same public port
// across oversized or otherwise failed receives, until closure/cancellation.
type UDPConn interface {
	ReadFrom([]byte) (int, netip.AddrPort, error)
	WriteTo([]byte, netip.AddrPort, bool) (int, error)
	LocalAddr() netip.AddrPort
	Close() error
}

// TooBig carries the path MTU from a synchronous write or an OS error queue.
type TooBig struct{ MTU uint32 }

func (e *TooBig) Error() string { return "datagram exceeds path MTU" }

// IsTooBig also recognizes native socket errors before adapter translation.
func IsTooBig(err error) bool {
	var big *TooBig
	return errors.As(err, &big) || errors.Is(err, syscall.EMSGSIZE) || errors.Is(err, syscall.Errno(10040)) // WSAEMSGSIZE
}

type DatagramError struct {
	Destination netip.AddrPort
	Payload     []byte
	MTU         uint32
	Unreachable bool
}

type UDPErrorQueue interface {
	ReadError(context.Context) (DatagramError, error)
}

// UDPErrorHandler lets an adapter deliver errors from its existing I/O paths.
// Install the handler before the first read or write. It must not block or
// call back into the socket. Error-queue state is unlocked before invocation.
type UDPErrorHandler interface {
	SetErrorHandler(func(DatagramError))
}

type LineDialer interface {
	DialTCP(context.Context, string, netip.AddrPort) (TCPConn, error)
	OpenUDP(context.Context, string, bool) (UDPConn, error)
}

// DestinationDialer lets an adapter ask the OS to choose a source address for
// the first datagram, then bind it for the lifetime of an unconnected mapping.
// This preserves endpoint-independent mapping on interfaces with many addresses.
type DestinationDialer interface {
	OpenUDPTo(context.Context, string, netip.AddrPort) (UDPConn, error)
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
	Interface string       `json:"interface,omitempty"`
	Addresses []netip.Addr `json:"addresses"`
}

// UDPNotifications is optional. Cancellation must stop the listener before
// the NAT is destroyed. A lost notification requests an immediate full dump.
type UDPNotifications interface {
	WatchUDP(context.Context, func(netip.AddrPort, string), func())
}

type ProbeResult struct {
	OK      bool          `json:"ok"`
	Outcome string        `json:"outcome,omitempty"`
	Latency time.Duration `json:"latency"`
	Error   string        `json:"error,omitempty"`
}

type Prober interface {
	Probe(context.Context, string, string) (ProbeResult, error)
}

type Echoer interface {
	Echo(context.Context, string, netip.Addr, []byte) ([]byte, error)
}
