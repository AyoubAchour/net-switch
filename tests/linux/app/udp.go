//go:build linux

package app

import (
	"context"
	"crypto/rand"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/AyoubAchour/net-switch/tests/linux/wire"
)

// Socket options not every Go release names in package syscall.
const (
	ipMTUDiscover   = 10 // IP_MTU_DISCOVER
	ipPMTUDiscDo    = 2  // IP_PMTUDISC_DO: set DF, never fragment locally
	ipv6MTUDiscover = 23 // IPV6_MTU_DISCOVER
	ipv6PMTUDiscDo  = 2
	ipv6DontFrag    = 62 // IPV6_DONTFRAG
)

func udpSocket(family6 bool, localPort int, df bool) (*net.UDPConn, error) {
	addr := netip.AddrPortFrom(netip.IPv4Unspecified(), uint16(localPort))
	network := "udp4"
	if family6 {
		addr, network = netip.AddrPortFrom(netip.IPv6Unspecified(), uint16(localPort)), "udp6"
	}
	lc := net.ListenConfig{Control: func(_, _ string, c syscall.RawConn) error {
		var serr error
		err := c.Control(func(fd uintptr) {
			serr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1)
			if serr == nil && df {
				if family6 {
					serr = errors.Join(
						syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IPV6, ipv6MTUDiscover, ipv6PMTUDiscDo),
						syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IPV6, ipv6DontFrag, 1))
				} else {
					serr = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IP, ipMTUDiscover, ipPMTUDiscDo)
				}
			}
		})
		if err != nil {
			return err
		}
		return serr
	}}
	pc, err := lc.ListenPacket(context.Background(), network, addr.String())
	if err != nil {
		return nil, err
	}
	return pc.(*net.UDPConn), nil
}

func token() string {
	var b [6]byte
	_, _ = rand.Read(b[:])
	return fmt.Sprintf("%x", b)
}

func payload(tok string, s, n, size int) []byte {
	msg := []byte(fmt.Sprintf("T:%s:%d:%d ", tok, s, n))
	for len(msg) < size {
		msg = append(msg, 'x')
	}
	return msg
}

// UDPResult is the udp mode's answer.
type UDPResult struct {
	Token      string         `json:"token"`
	Sent       int            `json:"sent"`
	Received   int            `json:"received"`
	Seen       map[string]int `json:"seen"` // the source each server saw, ip:port
	From       map[string]int `json:"from"` // the source of each reply as the app saw it
	SendErrors map[string]int `json:"sendErrors"`
	RecvErrors map[string]int `json:"recvErrors"`
	LocalPorts []int          `json:"localPorts"`
}

func runUDP(args []string) (any, error) {
	fs := flag.NewFlagSet("udp", flag.ContinueOnError)
	to := fs.String("to", "", "echo servers ip:port[,...]; every socket sends to each")
	count := fs.Int("count", 5, "datagrams per socket and server")
	sockets := fs.Int("sockets", 1, "sockets, one after another")
	interval := fs.Int("interval", 20, "ms between datagrams")
	size := fs.Int("size", 0, "pad each datagram to this many bytes")
	df := fs.Bool("df", false, "never fragment (DF / IPV6_DONTFRAG)")
	connect := fs.Bool("connect", false, "use a connected socket (one server), so ICMP errors are reported")
	wait := fs.Int("wait", 1500, "ms to wait for the last replies")
	localPort := fs.Int("local-port", 0, "source port")
	if err := parse(fs, args); err != nil {
		return nil, err
	}
	list, err := targets(*to)
	if err != nil {
		return nil, err
	}
	r := UDPResult{Token: token(), Seen: map[string]int{}, From: map[string]int{}, SendErrors: map[string]int{}, RecvErrors: map[string]int{}}
	for s := range *sockets {
		var conn *net.UDPConn
		if *connect {
			conn, err = connectedUDP(list[0], *localPort, *df)
		} else {
			conn, err = udpSocket(list[0].Addr().Is6(), *localPort, *df)
		}
		if err != nil {
			return nil, err
		}
		r.LocalPorts = append(r.LocalPorts, conn.LocalAddr().(*net.UDPAddr).Port)
		var mu sync.Mutex
		done := make(chan struct{})
		go func() {
			defer close(done)
			buf := make([]byte, 65536)
			for {
				n, from, err := conn.ReadFromUDPAddrPort(buf)
				if err != nil {
					if errors.Is(err, net.ErrClosed) {
						return
					}
					mu.Lock()
					r.RecvErrors[Code(err)]++
					mu.Unlock()
					if Code(err) == "TIMEOUT" {
						return
					}
					continue
				}
				seen, body, err := wire.ParseEchoReply(buf[:n])
				if err != nil || !strings.HasPrefix(string(body), "T:"+r.Token+":") {
					continue
				}
				mu.Lock()
				r.Received++
				r.Seen[seen.String()]++
				r.From[netip.AddrPortFrom(from.Addr().Unmap(), from.Port()).String()]++
				mu.Unlock()
			}
		}()
		for n := range *count {
			for _, target := range list {
				msg := payload(r.Token, s, n, *size)
				if *connect {
					_, err = conn.Write(msg)
				} else {
					_, err = conn.WriteToUDPAddrPort(msg, target)
				}
				mu.Lock()
				r.Sent++
				if err != nil {
					r.SendErrors[Code(err)]++
				}
				mu.Unlock()
			}
			time.Sleep(time.Duration(*interval) * time.Millisecond)
		}
		deadline := time.Now().Add(time.Duration(*wait) * time.Millisecond)
		for time.Now().Before(deadline) {
			mu.Lock()
			all := r.Received >= *count*len(list)*(s+1)
			mu.Unlock()
			if all {
				break
			}
			time.Sleep(20 * time.Millisecond)
		}
		_ = conn.Close()
		<-done
	}
	return r, nil
}

func connectedUDP(to netip.AddrPort, localPort int, df bool) (*net.UDPConn, error) {
	d := net.Dialer{Control: func(_, _ string, c syscall.RawConn) error {
		var serr error
		err := c.Control(func(fd uintptr) {
			serr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1)
			if serr == nil && df {
				if to.Addr().Is6() {
					serr = errors.Join(
						syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IPV6, ipv6MTUDiscover, ipv6PMTUDiscDo),
						syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IPV6, ipv6DontFrag, 1))
				} else {
					serr = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IP, ipMTUDiscover, ipPMTUDiscDo)
				}
			}
		})
		if err != nil {
			return err
		}
		return serr
	}}
	if localPort > 0 {
		local := netip.AddrPortFrom(netip.IPv4Unspecified(), uint16(localPort))
		if to.Addr().Is6() {
			local = netip.AddrPortFrom(netip.IPv6Unspecified(), uint16(localPort))
		}
		d.LocalAddr = net.UDPAddrFromAddrPort(local)
	}
	c, err := d.Dial("udp", to.String())
	if err != nil {
		return nil, err
	}
	return c.(*net.UDPConn), nil
}

// Event is something that happened at a time (Unix ms).
type Event struct {
	T    int64  `json:"t"`
	What string `json:"what"` // a reply's seen source, or an error code
}

// UDPStreamResult is the udpstream mode's answer.
type UDPStreamResult struct {
	Token      string  `json:"token"`
	LocalPort  int     `json:"localPort"`
	StartedAt  int64   `json:"startedAt"`
	EndedAt    int64   `json:"endedAt"`
	Sent       int     `json:"sent"`
	Replies    []Event `json:"replies"`
	SendErrors []Event `json:"sendErrors"`
	RecvErrors []Event `json:"recvErrors"`
}

func runUDPStream(args []string) (any, error) {
	fs := flag.NewFlagSet("udpstream", flag.ContinueOnError)
	to := fs.String("to", "", "echo server ip:port")
	localPort := fs.Int("local-port", 0, "source port")
	duration := fs.Int("duration", 3000, "ms of traffic")
	rate := fs.Int("rate", 50, "datagrams per second")
	connect := fs.Bool("connect", false, "use a connected socket, so ICMP errors are reported")
	tok := fs.String("token", "", "token to mark the datagrams with (default: random)")
	if err := parse(fs, args); err != nil {
		return nil, err
	}
	list, err := targets(*to)
	if err != nil {
		return nil, err
	}
	r := UDPStreamResult{Token: *tok, Replies: []Event{}, SendErrors: []Event{}, RecvErrors: []Event{}}
	if r.Token == "" {
		r.Token = token()
	}
	var conn *net.UDPConn
	if *connect {
		conn, err = connectedUDP(list[0], *localPort, false)
	} else {
		conn, err = udpSocket(list[0].Addr().Is6(), *localPort, false)
	}
	if err != nil {
		return nil, err
	}
	r.LocalPort = conn.LocalAddr().(*net.UDPAddr).Port
	var mu sync.Mutex
	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 65536)
		for {
			n, _, err := conn.ReadFromUDPAddrPort(buf)
			now := nowMS()
			if err != nil {
				if errors.Is(err, net.ErrClosed) {
					return
				}
				mu.Lock()
				r.RecvErrors = append(r.RecvErrors, Event{now, Code(err)})
				mu.Unlock()
				continue
			}
			seen, body, err := wire.ParseEchoReply(buf[:n])
			if err != nil || !strings.HasPrefix(string(body), "T:"+r.Token+":") {
				continue
			}
			mu.Lock()
			r.Replies = append(r.Replies, Event{now, seen.String()})
			mu.Unlock()
		}
	}()
	r.StartedAt = nowMS()
	end := time.Now().Add(time.Duration(*duration) * time.Millisecond)
	tick := time.Second / time.Duration(max(1, *rate))
	for i := 0; time.Now().Before(end); i++ {
		msg := payload(r.Token, 0, i, 0)
		if *connect {
			_, err = conn.Write(msg)
		} else {
			_, err = conn.WriteToUDPAddrPort(msg, list[0])
		}
		mu.Lock()
		r.Sent++
		if err != nil {
			r.SendErrors = append(r.SendErrors, Event{nowMS(), Code(err)})
		}
		mu.Unlock()
		time.Sleep(tick)
	}
	time.Sleep(300 * time.Millisecond)
	_ = conn.Close()
	<-done
	r.EndedAt = nowMS()
	return r, nil
}

// STUNResult is the stun mode's answer.
type STUNResult struct {
	LocalPort int               `json:"localPort"`
	Mapped    map[string]string `json:"mapped"` // server -> the address it saw
	Errors    map[string]string `json:"errors"`
	Acked     bool              `json:"acked"`
	Poked     bool              `json:"poked"`
	PokeFrom  string            `json:"pokeFrom,omitempty"`
}

func runSTUN(args []string) (any, error) {
	fs := flag.NewFlagSet("stun", flag.ContinueOnError)
	servers := fs.String("servers", "", "STUN servers ip:port,...")
	poke := fs.String("poke", "", "after the bindings, ask this server to have a third host send to us")
	wait := fs.Int("wait", 2000, "ms to wait for the poke")
	localPort := fs.Int("local-port", 0, "source port")
	if err := parse(fs, args); err != nil {
		return nil, err
	}
	list, err := targets(*servers)
	if err != nil {
		return nil, err
	}
	conn, err := udpSocket(list[0].Addr().Is6(), *localPort, false)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	r := STUNResult{LocalPort: conn.LocalAddr().(*net.UDPAddr).Port, Mapped: map[string]string{}, Errors: map[string]string{}}
	buf := make([]byte, 2048)
	for _, server := range list {
		var txid [12]byte
		_, _ = rand.Read(txid[:])
		got := false
		for try := 0; try < 3 && !got; try++ {
			if _, err := conn.WriteToUDPAddrPort(wire.STUNRequest(txid), server); err != nil {
				r.Errors[server.String()] = Code(err)
				break
			}
			deadline := time.Now().Add(400 * time.Millisecond)
			for !got && time.Now().Before(deadline) {
				_ = conn.SetReadDeadline(deadline)
				n, _, err := conn.ReadFromUDPAddrPort(buf)
				if err != nil {
					r.Errors[server.String()] = Code(err)
					break
				}
				if mapped, err := wire.ParseSTUNResponse(buf[:n], txid); err == nil {
					r.Mapped[server.String()] = mapped.String()
					delete(r.Errors, server.String())
					got = true
				}
			}
		}
	}
	if *poke != "" {
		pokeAt, err := netip.ParseAddrPort(*poke)
		if err != nil {
			return nil, usageError{err}
		}
		// The acknowledgement and the poke arrive in either order; wait for
		// each on its own, resending the request while either is missing.
		tok := token()
		deadline := time.Now().Add(time.Duration(*wait) * time.Millisecond)
		for try := 0; try < 3 && !(r.Acked && r.Poked) && time.Now().Before(deadline); try++ {
			if _, err := conn.WriteToUDPAddrPort([]byte("poke "+tok), pokeAt); err != nil {
				r.Errors["poke"] = Code(err)
				break
			}
			step := time.Now().Add(time.Duration(*wait/3) * time.Millisecond)
			if step.After(deadline) {
				step = deadline
			}
			for !(r.Acked && r.Poked) && time.Now().Before(step) {
				_ = conn.SetReadDeadline(step)
				n, from, err := conn.ReadFromUDPAddrPort(buf)
				if err != nil {
					break
				}
				text := string(buf[:n])
				switch {
				case strings.HasPrefix(text, "ack "):
					r.Acked = true
				case strings.HasPrefix(text, "poke "+tok+" from "):
					r.Poked = true
					r.PokeFrom = netip.AddrPortFrom(from.Addr().Unmap(), from.Port()).String()
				}
			}
		}
	}
	return r, nil
}

// BurstReply is one answered first datagram.
type BurstReply struct {
	Index int    `json:"i"`    // which destination it was sent to
	From  string `json:"from"` // the reply's source as the app saw it
	Seen  string `json:"seen"` // the source the server saw
}

// BurstResult is the udpburst mode's answer.
type BurstResult struct {
	Token      string         `json:"token"`
	LocalPort  int            `json:"localPort"`
	Sent       int            `json:"sent"`
	SpreadMS   float64        `json:"spreadMs"` // from the first send to the last
	To         []string       `json:"to"`
	Replies    []BurstReply   `json:"replies"`
	SendErrors map[string]int `json:"sendErrors"`
}

// runUDPBurst sends the first datagram to every destination at once from one
// socket: one goroutine per destination, released together, so they reach
// the engine while it's still deciding the new session.
func runUDPBurst(args []string) (any, error) {
	fs := flag.NewFlagSet("udpburst", flag.ContinueOnError)
	to := fs.String("to", "", "echo servers ip:port,...")
	wait := fs.Int("wait", 3000, "ms to wait for the replies")
	releaseFile := fs.String("release-file", "", "print the result, then keep the socket open until this file exists")
	if err := parse(fs, args); err != nil {
		return nil, err
	}
	list, err := targets(*to)
	if err != nil {
		return nil, err
	}
	conn, err := udpSocket(list[0].Addr().Is6(), 0, false)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	r := BurstResult{Token: token(), LocalPort: conn.LocalAddr().(*net.UDPAddr).Port, SendErrors: map[string]int{}, Replies: []BurstReply{}}
	for _, t := range list {
		r.To = append(r.To, t.String())
	}
	var mu sync.Mutex
	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 65536)
		for {
			n, from, err := conn.ReadFromUDPAddrPort(buf)
			if err != nil {
				return
			}
			seen, body, err := wire.ParseEchoReply(buf[:n])
			if err != nil {
				continue
			}
			fields := strings.Split(strings.TrimSpace(string(body)), ":")
			if len(fields) != 4 || fields[0] != "T" || fields[1] != r.Token {
				continue
			}
			var i int
			if _, err := fmt.Sscan(fields[3], &i); err != nil {
				continue
			}
			mu.Lock()
			r.Replies = append(r.Replies, BurstReply{Index: i, From: netip.AddrPortFrom(from.Addr().Unmap(), from.Port()).String(), Seen: seen.String()})
			mu.Unlock()
		}
	}()
	var first, last atomic.Int64
	first.Store(1 << 62)
	release := make(chan struct{})
	var wg sync.WaitGroup
	for i, target := range list {
		msg := payload(r.Token, 0, i, 0)
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-release
			now := time.Now().UnixMicro()
			_, err := conn.WriteToUDPAddrPort(msg, target)
			for {
				if old := first.Load(); now >= old || first.CompareAndSwap(old, now) {
					break
				}
			}
			for {
				if old := last.Load(); now <= old || last.CompareAndSwap(old, now) {
					break
				}
			}
			mu.Lock()
			r.Sent++
			if err != nil {
				r.SendErrors[Code(err)]++
			}
			mu.Unlock()
		}()
	}
	time.Sleep(50 * time.Millisecond) // every sender is parked on the release
	close(release)
	wg.Wait()
	r.SpreadMS = round(float64(last.Load()-first.Load()) / 1000)
	deadline := time.Now().Add(time.Duration(*wait) * time.Millisecond)
	for time.Now().Before(deadline) {
		mu.Lock()
		got := len(r.Replies)
		mu.Unlock()
		if got >= len(list) {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	// The socket, and so its session, stays open until the case releases it.
	mu.Lock()
	result := r
	result.Replies = slices.Clone(r.Replies)
	mu.Unlock()
	out, err := holdUntil(*releaseFile, result)
	_ = conn.Close()
	<-done
	return out, err
}

// FloodResult is the udpflood mode's answer.
type FloodResult struct {
	// Token marks every datagram: socket i sends "T:<token>:0:<i> ".
	Token      string         `json:"token"`
	Sockets    int            `json:"sockets"`
	Opened     int            `json:"opened"`
	Sent       int            `json:"sent"` // datagrams the kernel took
	Answered   int            `json:"answered"`
	Refused    int            `json:"refused"`
	Silent     int            `json:"silent"`
	OpenErrors map[string]int `json:"openErrors"`
	SendErrors map[string]int `json:"sendErrors"`
	// RefusedSockets are the sockets, by index, that got an ICMP unreachable.
	RefusedSockets []int `json:"refusedSockets"`
	// With --times, when each datagram went and each refusal arrived (Unix
	// ms).
	SentAt    []int64 `json:"sentAt,omitempty"`
	RefusedAt []int64 `json:"refusedAt,omitempty"`
}

// runUDPFlood opens many UDP sockets (each a new session to the engine), sends
// one datagram on each, then sees which are answered, refused (ICMP
// unreachable) or ignored. All sockets stay open until the end, or with
// --release-file until the case releases them.
func runUDPFlood(args []string) (any, error) {
	fs := flag.NewFlagSet("udpflood", flag.ContinueOnError)
	to := fs.String("to", "", "echo servers ip:port,...; socket i uses server i mod n")
	sockets := fs.Int("sockets", 1000, "sockets")
	rate := fs.Int("rate", 2000, "first datagrams per second")
	timeout := fs.Int("timeout", 3000, "ms to wait for answers after the last datagram")
	times := fs.Bool("times", false, "record when each refusal arrived")
	release := fs.String("release-file", "", "print the result, then keep every socket open until this file exists")
	if err := parse(fs, args); err != nil {
		return nil, err
	}
	list, err := targets(*to)
	if err != nil {
		return nil, err
	}
	r := FloodResult{Token: token(), Sockets: *sockets, OpenErrors: map[string]int{}, SendErrors: map[string]int{}, RefusedSockets: []int{}}
	tok := r.Token
	var conns []net.Conn
	for i := range *sockets {
		c, err := net.Dial("udp", list[i%len(list)].String())
		if err != nil {
			r.OpenErrors[Code(err)]++
			continue
		}
		conns = append(conns, c)
	}
	defer func() {
		for _, c := range conns {
			c.Close()
		}
	}()
	r.Opened = len(conns)
	var mu sync.Mutex
	var wg sync.WaitGroup
	sending := time.Duration(len(conns)) * time.Second / time.Duration(max(1, *rate))
	deadline := time.Now().Add(sending + time.Duration(*timeout)*time.Millisecond)
	tick := time.Second / time.Duration(max(1, *rate))
	next := time.Now()
	for i, c := range conns {
		if wait := time.Until(next); wait > 0 {
			time.Sleep(wait)
		}
		next = next.Add(tick)
		_, err := c.Write(payload(tok, 0, i, 0))
		mu.Lock()
		if err != nil {
			r.SendErrors[Code(err)]++
		} else {
			r.Sent++
			if *times {
				r.SentAt = append(r.SentAt, nowMS())
			}
		}
		mu.Unlock()
		wg.Add(1)
		go func() {
			defer wg.Done()
			buf := make([]byte, 2048)
			_ = c.SetReadDeadline(deadline)
			_, err := c.Read(buf)
			mu.Lock()
			defer mu.Unlock()
			switch Code(err) {
			case "":
				r.Answered++
			case "ECONNREFUSED":
				r.Refused++
				r.RefusedSockets = append(r.RefusedSockets, i)
				if *times {
					r.RefusedAt = append(r.RefusedAt, nowMS())
				}
			default:
				r.Silent++
			}
		}()
	}
	wg.Wait()
	return holdUntil(*release, r)
}
