//go:build linux

package app

import (
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/AyoubAchour/net-switch/tests/linux/wire"
)

// PingResult is the ping mode's answer.
type PingResult struct {
	Token    string         `json:"token"`
	Sent     int            `json:"sent"`
	Received int            `json:"received"`
	RTT      Stats          `json:"rttMs"`
	Errors   map[string]int `json:"errors"`
}

func runPing(args []string) (any, error) {
	fs := flag.NewFlagSet("ping", flag.ContinueOnError)
	to := fs.String("to", "", "address to ping")
	count := fs.Int("count", 3, "echo requests")
	interval := fs.Int("interval", 200, "ms between requests")
	timeout := fs.Int("timeout", 1500, "ms to wait for each reply")
	size := fs.Int("size", 56, "bytes of data per request")
	if err := parse(fs, args); err != nil {
		return nil, err
	}
	addr, err := netip.ParseAddr(*to)
	if err != nil {
		return nil, usageError{err}
	}
	r := PingResult{Token: token(), Errors: map[string]int{}}
	family, proto, request, reply := syscall.AF_INET, syscall.IPPROTO_ICMP, byte(8), byte(0)
	var sa syscall.Sockaddr
	if addr.Is6() {
		family, proto, request, reply = syscall.AF_INET6, syscall.IPPROTO_ICMPV6, 128, 129
		sa = &syscall.SockaddrInet6{Addr: addr.As16()}
	} else {
		sa = &syscall.SockaddrInet4{Addr: addr.As4()}
	}
	fd, err := syscall.Socket(family, syscall.SOCK_DGRAM|syscall.SOCK_CLOEXEC, proto)
	if err != nil {
		r.Errors["socket:"+Code(err)]++
		return r, nil
	}
	defer syscall.Close(fd)
	tv := syscall.NsecToTimeval((time.Duration(*timeout) * time.Millisecond).Nanoseconds())
	if err := syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &tv); err != nil {
		return nil, err
	}
	var rtts []float64
	buf := make([]byte, 65536)
	base := uint16(rand.IntN(30000))
	for i := range *count {
		seq := base + uint16(i)
		data := []byte(fmt.Sprintf("T:%s:%d ", r.Token, i))
		for len(data) < *size {
			data = append(data, 'x')
		}
		msg := append([]byte{request, 0, 0, 0, 0, 0, byte(seq >> 8), byte(seq)}, data...)
		start := time.Now()
		r.Sent++
		if err := syscall.Sendto(fd, msg, 0, sa); err != nil {
			r.Errors["send:"+Code(err)]++
			time.Sleep(time.Duration(*interval) * time.Millisecond)
			continue
		}
		deadline := start.Add(time.Duration(*timeout) * time.Millisecond)
		for time.Now().Before(deadline) {
			n, _, err := syscall.Recvfrom(fd, buf, 0)
			if err != nil {
				if err == syscall.EAGAIN || err == syscall.EINTR {
					if err == syscall.EAGAIN {
						r.Errors["TIMEOUT"]++
						break
					}
					continue
				}
				r.Errors["recv:"+Code(err)]++
				break
			}
			if n >= 8 && buf[0] == reply && binary.BigEndian.Uint16(buf[6:]) == seq {
				r.Received++
				rtts = append(rtts, msSince(start))
				break
			}
		}
		time.Sleep(time.Duration(*interval) * time.Millisecond)
	}
	r.RTT = Summarise(rtts)
	return r, nil
}

// DNSResult is the dns mode's answer.
type DNSResult struct {
	wire.DNSResult
	UDPTruncated bool    `json:"udpTruncated"`
	TCPFallback  bool    `json:"tcpFallback"`
	Err          string  `json:"err,omitempty"`
	MS           float64 `json:"ms"`
}

func runDNS(args []string) (any, error) {
	fs := flag.NewFlagSet("dns", flag.ContinueOnError)
	server := fs.String("server", "", "DNS server ip:port")
	name := fs.String("name", "whoami.test", "name to look up")
	kind := fs.String("type", "A", "A, AAAA or TXT")
	edns := fs.Int("edns", 0, "advertise this UDP payload size (EDNS0)")
	tcpOnly := fs.Bool("tcp", false, "ask over TCP only")
	timeout := fs.Int("timeout", 3000, "ms per attempt")
	if err := parse(fs, args); err != nil {
		return nil, err
	}
	list, err := targets(*server)
	if err != nil {
		return nil, err
	}
	qtype, err := wire.DNSTypeByName(*kind)
	if err != nil {
		return nil, usageError{err}
	}
	id := uint16(rand.IntN(65536))
	query, err := wire.BuildDNSQuery(id, *name, qtype, uint16(*edns))
	if err != nil {
		return nil, usageError{err}
	}
	r := DNSResult{}
	start := time.Now()
	deadline := func() time.Time { return time.Now().Add(time.Duration(*timeout) * time.Millisecond) }
	if !*tcpOnly {
		conn, err := net.Dial("udp", list[0].String())
		if err != nil {
			r.Err = Code(err)
			return r, nil
		}
		_ = conn.SetDeadline(deadline())
		_, err = conn.Write(query)
		buf := make([]byte, 65536)
		n := 0
		if err == nil {
			n, err = conn.Read(buf)
		}
		conn.Close()
		if err != nil {
			r.Err = "udp:" + Code(err)
			r.MS = msSince(start)
			return r, nil
		}
		res, err := wire.ParseDNSAnswer(buf[:n], id)
		if err != nil {
			r.Err = "udp:" + err.Error()
			return r, nil
		}
		r.DNSResult, r.UDPTruncated = res, res.Truncated
		if !res.Truncated {
			r.MS = msSince(start)
			return r, nil
		}
		r.TCPFallback = true
	}
	conn, err := net.DialTimeout("tcp", list[0].String(), time.Duration(*timeout)*time.Millisecond)
	if err != nil {
		r.Err = "tcp:" + Code(err)
		return r, nil
	}
	defer conn.Close()
	_ = conn.SetDeadline(deadline())
	if _, err := conn.Write(append(binary.BigEndian.AppendUint16(nil, uint16(len(query))), query...)); err != nil {
		r.Err = "tcp:" + Code(err)
		return r, nil
	}
	var size [2]byte
	if _, err := io.ReadFull(conn, size[:]); err != nil {
		r.Err = "tcp:" + Code(err)
		return r, nil
	}
	answer := make([]byte, binary.BigEndian.Uint16(size[:]))
	if _, err := io.ReadFull(conn, answer); err != nil {
		r.Err = "tcp:" + Code(err)
		return r, nil
	}
	res, err := wire.ParseDNSAnswer(answer, id)
	if err != nil {
		r.Err = "tcp:" + err.Error()
		return r, nil
	}
	r.DNSResult = res
	r.MS = msSince(start)
	return r, nil
}

func runHoldFiles(args []string) (any, error) {
	fs := flag.NewFlagSet("holdfiles", flag.ContinueOnError)
	count := fs.Int("count", 5000, "files to keep open")
	seconds := fs.Int("seconds", 600, "give up after this long")
	if err := parse(fs, args); err != nil {
		return nil, err
	}
	files := make([]*os.File, 0, *count)
	for range *count {
		f, err := os.Open("/dev/null")
		if err != nil {
			return nil, fmt.Errorf("opened %d of %d files: %w", len(files), *count, err)
		}
		files = append(files, f)
	}
	fmt.Printf("{\"holding\":%d}\n", len(files))
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGTERM, syscall.SIGINT)
	select {
	case <-stop:
	case <-time.After(time.Duration(*seconds) * time.Second):
	}
	for _, f := range files {
		f.Close()
	}
	return nil, nil
}
