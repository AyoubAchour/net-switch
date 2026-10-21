//go:build linux

package linux

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/AyoubAchour/net-switch/internal/engine/platform"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// These tests use real Linux ICMP errors in the CI's private network
// namespace: nft REJECT rules and forged Packet Too Big messages on loopback.

func kernelLoopback(t *testing.T) {
	t.Helper()
	requireKernelNamespace(t)
	lo, err := netlink.LinkByName("lo")
	if err != nil {
		t.Fatal(err)
	}
	if err := netlink.LinkSetUp(lo); err != nil {
		t.Fatal(err)
	}
}

// kernelUDPSocket matches OpenUDPTo's error-queue options without a line.
func kernelUDPSocket(t *testing.T, ip string) (*udpSocket, chan platform.DatagramError) {
	t.Helper()
	addr := netip.MustParseAddr(ip)
	network := "udp4"
	if addr.Is6() {
		network = "udp6"
	}
	conn, err := net.ListenUDP(network, net.UDPAddrFromAddrPort(netip.AddrPortFrom(addr, 0)))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := conn.SyscallConn()
	if err != nil {
		conn.Close()
		t.Fatal(err)
	}
	var optionErr error
	err = raw.Control(func(fd uintptr) {
		if addr.Is6() {
			optionErr = unix.SetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_RECVERR, 1)
		} else {
			optionErr = unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_RECVERR, 1)
		}
	})
	if err != nil || optionErr != nil {
		conn.Close()
		t.Fatalf("error queue: %v %v", err, optionErr)
	}
	s := &udpSocket{conn: conn, raw: raw, v6: addr.Is6(), errors: make(chan platform.DatagramError, 1), done: make(chan struct{})}
	t.Cleanup(func() { s.Close() })
	notes := make(chan platform.DatagramError, 64)
	s.SetErrorHandler(func(e platform.DatagramError) {
		select {
		case notes <- e:
		default:
			t.Error("error notifications overflowed")
		}
	})
	return s, notes
}

func kernelListener(t *testing.T, ip string) (*net.UDPConn, netip.AddrPort) {
	t.Helper()
	conn, err := net.ListenUDP("udp", net.UDPAddrFromAddrPort(netip.AddrPortFrom(netip.MustParseAddr(ip), 0)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	return conn, conn.LocalAddr().(*net.UDPAddr).AddrPort()
}

func expectDatagram(t *testing.T, conn *net.UDPConn, want string) {
	t.Helper()
	var data [64]byte
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, _, err := conn.ReadFromUDPAddrPort(data[:])
	if err != nil || string(data[:n]) != want {
		t.Fatalf("listener got %q %v, want %q", data[:max(n, 0)], err, want)
	}
}

func nftInput(t *testing.T, family, table, rule string) {
	t.Helper()
	script := fmt.Sprintf("table %s %s {\n\tchain input {\n\t\ttype filter hook input priority 0; policy accept;\n\t\t%s\n\t}\n}\n", family, table, rule)
	cmd := exec.Command("nft", "-f", "-")
	cmd.Stdin = strings.NewReader(script)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("nft %s: %v %s", script, err, out)
	}
	t.Cleanup(func() { exec.Command("nft", "delete", "table", family, table).Run() })
}

// waitQueuedError waits for EPOLLERR's poll equivalent: a latched error or a
// non-empty error queue. It consumes nothing.
func waitQueuedError(t *testing.T, s *udpSocket) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		var revents int16
		var pollErr error
		s.raw.Control(func(fd uintptr) {
			fds := []unix.PollFd{{Fd: int32(fd)}}
			_, pollErr = unix.Poll(fds, 50)
			revents = fds[0].Revents
		})
		if pollErr == nil && revents&unix.POLLERR != 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("ICMP error never reached the socket")
		}
	}
}

func sockaddrOf(dst netip.AddrPort) unix.Sockaddr {
	if dst.Addr().Is4() {
		return &unix.SockaddrInet4{Addr: dst.Addr().As4(), Port: int(dst.Port())}
	}
	return &unix.SockaddrInet6{Addr: dst.Addr().As16(), Port: int(dst.Port())}
}

// plainSend is a send without our attribution: the kernel's raw behavior.
func plainSend(s *udpSocket, b []byte, dst netip.AddrPort) error {
	var sendErr error
	s.raw.Control(func(fd uintptr) { sendErr = unix.Sendto(int(fd), b, unix.MSG_DONTWAIT, sockaddrOf(dst)) })
	return sendErr
}

func queuedErrors(s *udpSocket) int {
	var data [2048]byte
	var control [256]byte
	count := 0
	for count < 1000 {
		var err error
		s.raw.Control(func(fd uintptr) {
			_, _, _, _, err = unix.Recvmsg(int(fd), data[:], control[:], unix.MSG_ERRQUEUE|unix.MSG_DONTWAIT)
		})
		if err != nil {
			break
		}
		count++
	}
	return count
}

func takeNotification(t *testing.T, notes chan platform.DatagramError) platform.DatagramError {
	t.Helper()
	select {
	case e := <-notes:
		return e
	default:
		t.Fatal("no error notification was delivered")
		return platform.DatagramError{}
	}
}

func expectNoNotification(t *testing.T, notes chan platform.DatagramError) {
	t.Helper()
	select {
	case e := <-notes:
		t.Fatalf("unexpected error notification: %+v", e)
	default:
	}
}

func TestKernelUDPCrossDestinationICMPErrors(t *testing.T) {
	kernelLoopback(t)
	for _, tc := range []struct {
		name, ip, family, reject string
		errno                    unix.Errno
	}{
		{"host-unreachable", "127.0.0.1", "ip", "icmp type host-unreachable", unix.EHOSTUNREACH},
		{"net-unreachable", "127.0.0.1", "ip", "icmp type net-unreachable", unix.ENETUNREACH},
		{"v6-admin-prohibited", "::1", "ip6", "icmpv6 type admin-prohibited", unix.EACCES},
		{"v6-address-unreachable", "::1", "ip6", "icmpv6 type addr-unreachable", unix.EHOSTUNREACH},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, notes := kernelUDPSocket(t, tc.ip)
			// A has a listener, so its error comes from the REJECT rule and
			// not from a closed port.
			_, a := kernelListener(t, tc.ip)
			healthy, b := kernelListener(t, tc.ip)
			nftInput(t, tc.family, "nsudperr", fmt.Sprintf("udp dport %d reject with %s", a.Port(), tc.reject))

			// Starting condition: Linux hands A's ICMP error to the next send
			// even though it targets healthy B.
			if _, err := s.TryWriteTo([]byte("A first"), a, false); err != nil {
				t.Fatal(err)
			}
			waitQueuedError(t, s)
			if err := plainSend(s, []byte("unattributed"), b); err != tc.errno {
				t.Fatalf("kernel did not latch A's error into B's send: %v, want %v", err, tc.errno)
			}
			s.drainErrors()
			takeNotification(t, notes)

			if _, err := s.TryWriteTo([]byte("A again"), a, false); err != nil {
				t.Fatal(err)
			}
			waitQueuedError(t, s)
			if n, err := s.TryWriteTo([]byte("to B"), b, false); err != nil || n != 4 {
				t.Fatalf("A's %v lost or fabricated an error for B: %d %v", tc.errno, n, err)
			}
			expectDatagram(t, healthy, "to B")
			e := takeNotification(t, notes)
			if e.Destination != a || !e.Unreachable || e.MTU != 0 || string(e.Payload) != "A again" {
				t.Fatalf("notification did not name A with its own quotation: %+v", e)
			}
			expectNoNotification(t, notes)
			if left := queuedErrors(s); left != 0 {
				t.Fatalf("%d errors left after recovery", left)
			}
		})
	}
}

func icmpInDestUnreachs(t *testing.T) uint64 {
	t.Helper()
	b, err := os.ReadFile("/proc/net/snmp")
	if err != nil {
		t.Fatal(err)
	}
	var header []string
	for _, line := range strings.Split(string(b), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 || fields[0] != "Icmp:" {
			continue
		}
		if header == nil {
			header = fields
			continue
		}
		for i, name := range header {
			if name == "InDestUnreachs" && i < len(fields) {
				v, err := strconv.ParseUint(fields[i], 10, 64)
				if err != nil {
					t.Fatal(err)
				}
				return v
			}
		}
	}
	t.Fatal("no Icmp InDestUnreachs in /proc/net/snmp")
	return 0
}

func TestKernelUDPQueuedErrorsStayBounded(t *testing.T) {
	kernelLoopback(t)
	s, notes := kernelUDPSocket(t, "127.0.0.1")
	_, a := kernelListener(t, "127.0.0.1")
	healthy, b := kernelListener(t, "127.0.0.1")
	nftInput(t, "ip", "nsudpflood", fmt.Sprintf("udp dport %d reject with icmp type host-unreachable", a.Port()))
	const queued = errorDrainLimit + 4
	base := icmpInDestUnreachs(t)
	// Plain sends keep every report queued. A send that returns the previous
	// report's latched error sent nothing, so repeat it.
	for sent, attempts := 0, 0; sent < queued; attempts++ {
		if attempts > 3*queued {
			t.Fatal("could not queue the ICMP errors")
		}
		switch err := plainSend(s, []byte("A"), a); err {
		case nil:
			sent++
		case unix.EHOSTUNREACH:
		default:
			t.Fatalf("send to A: %v", err)
		}
	}
	// Starting condition: every REJECT came back. Delivery to the error
	// queue follows the counter in the same softirq.
	for deadline := time.Now().Add(2 * time.Second); icmpInDestUnreachs(t) < base+queued; {
		if time.Now().After(deadline) {
			t.Fatalf("only %d of %d ICMP errors arrived", icmpInDestUnreachs(t)-base, queued)
		}
		time.Sleep(5 * time.Millisecond)
	}
	time.Sleep(20 * time.Millisecond)
	waitQueuedError(t, s)
	start := time.Now()
	if n, err := s.TryWriteTo([]byte("to B"), b, false); err != nil || n != 4 {
		t.Fatalf("a full error queue fabricated an error for B: %d %v", n, err)
	}
	elapsed := time.Since(start)
	expectDatagram(t, healthy, "to B")
	if e := takeNotification(t, notes); e.Destination != a || !e.Unreachable {
		t.Fatalf("wrong notification: %+v", e)
	}
	expectNoNotification(t, notes)
	// One bounded pass consumed exactly errorDrainLimit reports; the rest stay
	// queued for the reader's level-triggered EPOLLERR.
	if left := queuedErrors(s); left != queued-errorDrainLimit {
		t.Fatalf("send consumed %d of %d queued errors, want exactly %d (elapsed %v)", queued-left, queued, errorDrainLimit, elapsed)
	}
}

// forgePacketTooBig sends a real ICMPv4 fragmentation-needed message to the
// local stack, quoting a datagram from local to quoted.
func forgePacketTooBig(t *testing.T, local, quoted netip.AddrPort, mtu uint16, payload string) {
	t.Helper()
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.IPPROTO_ICMP)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)
	inner := 20 + 8 + len(payload)
	b := make([]byte, 8+inner)
	b[0], b[1] = 3, 4
	binary.BigEndian.PutUint16(b[6:], mtu)
	ip := b[8:]
	ip[0], ip[8], ip[9] = 0x45, 64, unix.IPPROTO_UDP
	binary.BigEndian.PutUint16(ip[2:], uint16(inner))
	binary.BigEndian.PutUint16(ip[6:], 0x4000)
	source, destination := netip.MustParseAddr("127.0.0.1").As4(), quoted.Addr().As4()
	copy(ip[12:], source[:])
	copy(ip[16:], destination[:])
	udp := ip[20:]
	binary.BigEndian.PutUint16(udp[0:], local.Port())
	binary.BigEndian.PutUint16(udp[2:], quoted.Port())
	binary.BigEndian.PutUint16(udp[4:], uint16(8+len(payload)))
	copy(udp[8:], payload)
	var sum uint32
	for i := 0; i+1 < len(b); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(b[i:]))
	}
	if len(b)%2 == 1 {
		sum += uint32(b[len(b)-1]) << 8
	}
	for sum > 0xffff {
		sum = sum&0xffff + sum>>16
	}
	binary.BigEndian.PutUint16(b[2:], ^uint16(sum))
	if err := unix.Sendto(fd, b, 0, &unix.SockaddrInet4{Addr: source}); err != nil {
		t.Fatal(err)
	}
}

func TestKernelUDPStalePacketTooBigAndLocalMTU(t *testing.T) {
	kernelLoopback(t)
	// A 1280-byte line gives a deterministic local EMSGSIZE.
	link := &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: "udperr0", MTU: 1280}}
	if err := netlink.LinkAdd(link); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { netlink.LinkDel(link) })
	if err := netlink.LinkSetUp(link); err != nil {
		t.Fatal(err)
	}
	if err := netlink.AddrAdd(link, &netlink.Addr{IPNet: prefix("192.0.2.1/24")}); err != nil {
		t.Fatal(err)
	}
	s, notes := kernelUDPSocket(t, "0.0.0.0")
	local := netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), s.LocalAddr().Port())
	_, a := kernelListener(t, "127.0.0.2")
	healthy, b := kernelListener(t, "127.0.0.3")
	c := netip.MustParseAddrPort("192.0.2.77:9")

	// Starting condition: A's remote Packet Too Big fails B's small send.
	if _, err := s.TryWriteTo([]byte("A"), a, true); err != nil {
		t.Fatal(err)
	}
	forgePacketTooBig(t, local, a, 1200, "A")
	waitQueuedError(t, s)
	if err := plainSend(s, []byte("unattributed"), b); err != unix.EMSGSIZE {
		t.Fatalf("kernel did not latch A's Packet Too Big into B's send: %v", err)
	}
	s.drainErrors()
	takeNotification(t, notes)

	forgePacketTooBig(t, local, a, 1200, "A")
	waitQueuedError(t, s)
	if n, err := s.TryWriteTo([]byte("to B"), b, true); err != nil || n != 4 {
		t.Fatalf("A's Packet Too Big became B's: %d %v", n, err)
	}
	expectDatagram(t, healthy, "to B")
	if e := takeNotification(t, notes); e.Destination != a || e.MTU != 1200 || e.Unreachable || string(e.Payload) != "A" {
		t.Fatalf("remote Packet Too Big did not name A with its MTU: %+v", e)
	}

	// B's own local too big while A's remote one is queued: the local MTU
	// of C's line wins, and A is still told its own MTU.
	forgePacketTooBig(t, local, a, 1100, "A")
	waitQueuedError(t, s)
	_, err := s.TryWriteTo(make([]byte, 1400), c, true)
	var big *platform.TooBig
	if !errors.As(err, &big) || big.MTU != 1280 {
		t.Fatalf("local too big was reclassified by a queued remote error: %v", err)
	}
	if e := takeNotification(t, notes); e.Destination != a || e.MTU != 1100 {
		t.Fatalf("queued remote Packet Too Big was not delivered for A: %+v", e)
	}
	expectNoNotification(t, notes)

	// With nothing queued, the local error is still synchronous and
	// carries no fabricated quotation.
	_, err = s.TryWriteTo(make([]byte, 1400), c, true)
	if !errors.As(err, &big) || big.MTU != 1280 {
		t.Fatalf("plain local too big: %v", err)
	}
	expectNoNotification(t, notes)
	if left := queuedErrors(s); left != 0 {
		t.Fatalf("%d errors left after local too big", left)
	}
}
