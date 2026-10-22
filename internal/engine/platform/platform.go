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

// TunIOContext optionally installs a single cancellation hook for the forwarding
// lifetime. Call once before starting I/O. Per-call contexts still work normally;
// implementations may avoid per-packet hooks only for this same Done channel.
type TunIOContext interface{ BindIOContext(context.Context) }

// TunCloseStarter optionally interrupts I/O and begins native teardown without
// waiting. Close must still join teardown and return its result. The engine
// overlaps this work with route cleanup, and joins before acknowledging stop.
type TunCloseStarter interface{ BeginClose() }

// RouteQuiescer stops and joins background route repair before teardown can
// remove the TUN. Cancelling sibling contexts alone does not order their work.
type RouteQuiescer interface{ Quiesce() }

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

// ReadyTCP optionally transfers a connection to the nonblocking relay. Arm
// replaces its one-shot interest; readiness invokes wake without doing I/O.
// Detach removes the registration before the socket can be closed or reused.
// TryRead/TryWrite report ErrWouldBlock without waiting or changing deadlines.
// A successful Watch transfers exclusive I/O ownership: callers then use only
// TryRead/TryWrite, addresses, shutdown, linger and Close, not blocking I/O or
// deadlines. An adapter may release its original Go poll descriptor at transfer.
var ErrWouldBlock = errors.New("socket would block")

// ErrDatagramDropped is a local resource drop or an asynchronous error already
// handled using its original destination. Count it without inventing an ICMP
// unreachable for the datagram currently being sent.
var ErrDatagramDropped = errors.New("datagram dropped")

type ReadyTCP interface {
	TCPConn
	TryRead([]byte) (int, error)
	// TryPeek leaves bytes in the source socket. TryDiscard consumes at most
	// len(scratch) bytes already peeked and accepted by the destination. Both
	// are nonblocking; the relay exclusively owns reads between these calls.
	// Linux can discard with MSG_TRUNC; Windows may read into scratch.
	TryPeek([]byte) (int, error)
	TryDiscard(scratch []byte) (int, error)
	TryWrite([]byte) (int, error)
	Watch(func()) (Readiness, error)
}
type Readiness interface {
	// Re-arm is level triggered: already-ready data, EOF, or write space
	// must wake the caller again without requiring a new edge. Watch and Arm
	// must not wait for I/O or worker progress; callbacks only enqueue work.
	Arm(read, write bool) error
	Detach()
}

// ReadFrom errors describe individual datagrams unless errors.Is(net.ErrClosed).
// Translate EMSGSIZE/WSAEMSGSIZE to TooBig; other receive errors remain
// recoverable. Close unblocks ReadFrom. The NAT keeps the same public port
// across oversized or otherwise failed receives, until closure/cancellation.
type UDPConn interface {
	// WaitReadable must not consume a datagram. Close interrupts the wait.
	// The NAT borrows receive storage only after this reports readiness.
	WaitReadable(context.Context) error
	ReadFrom([]byte) (int, netip.AddrPort, error)
	WriteTo([]byte, netip.AddrPort, bool) (int, error)
	LocalAddr() netip.AddrPort
	Close() error
}

// ReadyUDP runs datagram I/O without parking a goroutine for each mapping.
// Watch and Detach have the same lifetime rules as ReadyTCP. A datagram write
// either succeeds whole or returns an error; ErrWouldBlock consumes nothing.
// An empty datagram returns zero bytes with a valid source and nil error.
// Asynchronous error records use UDPErrorHandler during Try operations; the
// blocking UDPErrorQueue interface is only used by the legacy UDPConn path.
type ReadyUDP interface {
	UDPConn
	// Watch installs bounded readiness bookkeeping without waiting for I/O or
	// a worker. It may run under the session lock also used by packet ingress.
	Watch(func()) (Readiness, error)
	TryReadFrom([]byte) (int, netip.AddrPort, error)
	TryWriteTo([]byte, netip.AddrPort, bool) (int, error)
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

// FlowIdentity is the flow an outbound socket serves: its owner, the app's
// own endpoint and its first destination. A platform records it with a
// refused open, so the refusal can be traced to the flow it hit.
type FlowIdentity struct {
	Owner       Owner
	Source      netip.AddrPort
	Destination netip.AddrPort
}

// FlowDialer is an optional LineDialer extension that is told which flow a
// socket is for. Dialers without it get the plain calls.
type FlowDialer interface {
	DialFlowTCP(context.Context, string, netip.AddrPort, FlowIdentity) (TCPConn, error)
	OpenFlowUDP(context.Context, string, bool, FlowIdentity) (UDPConn, error)
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
