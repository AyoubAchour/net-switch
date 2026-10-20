//go:build linux

// Package app is the test app: "nsapp app <mode>". Copies of the harness
// binary at different paths (/opt/nsapps/alpha/nsapp, .../bravo/nsapp, ...) are
// different apps to the engine. Each mode does one kind of traffic and prints
// one JSON object describing what happened; network failures are part of that
// result, not an exit code. Exit codes: 0 done, 1 broken, 2 bad usage.
package app

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"slices"
	"strings"
	"syscall"
	"time"
)

type mode struct {
	run   func(args []string) (any, error)
	about string
}

var modes = map[string]mode{
	"tcp":         {runTCP, "TCP connections to whoami servers"},
	"reuse":       {runReuse, "TCP connections again and again from one source port"},
	"tcphold":     {runTCPHold, "many TCP connections held open at once"},
	"udpburst":    {runUDPBurst, "first datagrams to many destinations at once, from one socket"},
	"udpflood":    {runUDPFlood, "one datagram on each of thousands of UDP sockets"},
	"udpqueue":    {runUDPQueue, "paced datagrams on held UDP sockets to exercise byte and output queues"},
	"stream":      {runStream, "one long TCP connection, pinging"},
	"bulk":        {runBulk, "a hashed TCP download or upload"},
	"bulkhold":    {runBulkHold, "a full-speed download that then trickles, every byte checked, held until released"},
	"http":        {runHTTP, "one HTTP GET; the body is the source the server saw"},
	"udp":         {runUDP, "UDP datagrams to echo servers"},
	"udpstream":   {runUDPStream, "continuous UDP from one source port"},
	"stun":        {runSTUN, "STUN bindings from one socket, and a poke from a third host"},
	"ping":        {runPing, "ICMP echo through an unprivileged ping socket"},
	"dns":         {runDNS, "one DNS query, falling back to TCP when truncated"},
	"holdfiles":   {runHoldFiles, "keep many files open until killed"},
	"fdpass-send": {runFDPassSend, "create a TCP socket and hand it to another process"},
	"fdpass-recv": {runFDPassRecv, "receive a TCP socket and connect it"},
	"share-exec":  {runShareExec, "create a TCP socket and start a program that inherits it"},
	"connect-fd":  {runConnectFD, "connect an inherited TCP socket"},
	"spawn":       {runSpawn, "start another program (fork and exec) and pass on its result"},
}

// Main is "nsaccept app <mode> [flags]".
func Main(args []string) int {
	if os.Getenv("NETSWITCH_TEST_LARGE_FLATPAK") == "1" {
		st, err := os.Stat("/.flatpak-info")
		if err != nil || st.Size() <= 64<<10 {
			fmt.Fprintln(os.Stderr, "large Flatpak metadata fixture did not exceed 64 KiB:", st, err)
			return 1
		}
		fmt.Fprintln(os.Stderr, "verified Flatpak metadata size:", st.Size())
	}
	if len(args) == 0 || modes[args[0]].run == nil {
		names := make([]string, 0, len(modes))
		for name, m := range modes {
			names = append(names, fmt.Sprintf("  %-12s %s", name, m.about))
		}
		slices.Sort(names)
		fmt.Fprintf(os.Stderr, "usage: nsapp app <mode> [flags]\n%s\n", strings.Join(names, "\n"))
		return 2
	}
	result, err := modes[args[0]].run(args[1:])
	if err != nil {
		var usage usageError
		fmt.Fprintf(os.Stderr, "%s: %v\n", args[0], err)
		if errors.As(err, &usage) || errors.Is(err, flag.ErrHelp) {
			return 2
		}
		return 1
	}
	if result != nil {
		if err := json.NewEncoder(os.Stdout).Encode(result); err != nil {
			return 1
		}
	}
	return 0
}

type usageError struct{ error }

func parse(fs *flag.FlagSet, args []string) error {
	fs.SetOutput(io.Discard)
	if err := fs.Parse(args); err != nil {
		return usageError{err}
	}
	return nil
}

// Code names a network error the way results report it.
func Code(err error) string {
	var netErr net.Error
	switch {
	case err == nil:
		return ""
	case errors.Is(err, os.ErrDeadlineExceeded) || (errors.As(err, &netErr) && netErr.Timeout()):
		return "TIMEOUT"
	case errors.Is(err, io.EOF):
		return "EOF"
	}
	for _, e := range []syscall.Errno{
		syscall.ECONNREFUSED, syscall.ECONNRESET, syscall.ECONNABORTED, syscall.EHOSTUNREACH, syscall.ENETUNREACH,
		syscall.EMSGSIZE, syscall.EPIPE, syscall.EADDRINUSE, syscall.EADDRNOTAVAIL, syscall.ETIMEDOUT,
		syscall.EINVAL, syscall.EPERM, syscall.EACCES, syscall.ENETDOWN, syscall.EAFNOSUPPORT,
	} {
		if errors.Is(err, e) {
			return errnoName(e)
		}
	}
	return err.Error()
}

func errnoName(e syscall.Errno) string {
	names := map[syscall.Errno]string{
		syscall.ECONNREFUSED: "ECONNREFUSED", syscall.ECONNRESET: "ECONNRESET", syscall.ECONNABORTED: "ECONNABORTED",
		syscall.EHOSTUNREACH: "EHOSTUNREACH", syscall.ENETUNREACH: "ENETUNREACH", syscall.EMSGSIZE: "EMSGSIZE",
		syscall.EPIPE: "EPIPE", syscall.EADDRINUSE: "EADDRINUSE", syscall.EADDRNOTAVAIL: "EADDRNOTAVAIL",
		syscall.ETIMEDOUT: "ETIMEDOUT", syscall.EINVAL: "EINVAL", syscall.EPERM: "EPERM", syscall.EACCES: "EACCES",
		syscall.ENETDOWN: "ENETDOWN", syscall.EAFNOSUPPORT: "EAFNOSUPPORT",
	}
	if name, ok := names[e]; ok {
		return name
	}
	return e.Error()
}

// Stats summarise durations in milliseconds.
type Stats struct {
	N   int     `json:"n"`
	P50 float64 `json:"p50"`
	P95 float64 `json:"p95"`
	Max float64 `json:"max"`
}

// Summarise computes Stats over values in milliseconds.
func Summarise(values []float64) Stats {
	if len(values) == 0 {
		return Stats{}
	}
	sorted := slices.Clone(values)
	slices.Sort(sorted)
	at := func(p float64) float64 {
		i := int(p * float64(len(sorted)))
		if i >= len(sorted) {
			i = len(sorted) - 1
		}
		return round(sorted[i])
	}
	return Stats{N: len(sorted), P50: at(0.50), P95: at(0.95), Max: round(sorted[len(sorted)-1])}
}

func round(ms float64) float64 { return float64(int64(ms*100+0.5)) / 100 }

func msSince(t time.Time) float64 { return round(float64(time.Since(t).Microseconds()) / 1000) }

func nowMS() int64 { return time.Now().UnixMilli() }

func targets(list string) ([]netip.AddrPort, error) {
	var out []netip.AddrPort
	for _, item := range strings.Split(list, ",") {
		if item = strings.TrimSpace(item); item == "" {
			continue
		}
		ap, err := netip.ParseAddrPort(item)
		if err != nil {
			return nil, usageError{fmt.Errorf("bad address %q: %w", item, err)}
		}
		out = append(out, ap)
	}
	if len(out) == 0 {
		return nil, usageError{errors.New("--to is required")}
	}
	return out, nil
}

// waitFile blocks until path exists (if path isn't empty), for up to timeout.
func waitFile(path string, timeout time.Duration) error {
	if path == "" {
		return nil
	}
	deadline := time.Now().Add(timeout)
	for {
		if _, err := os.Stat(path); err == nil {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("%s didn't appear within %s", path, timeout)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// ReleaseTimeout bounds how long a mode holds its sockets for a case that
// never releases them (the case's own cleanup kills the app sooner).
const ReleaseTimeout = 10 * time.Minute

// holdUntil is the release barrier: with release set, it prints the result
// at once and returns only when that file exists, so whatever the mode still
// holds open (its sockets) stays alive while the case checks the engine. The
// result is then already printed. Without release it hands the result back
// for Main to print.
func holdUntil(release string, result any) (any, error) {
	if release == "" {
		return result, nil
	}
	if err := json.NewEncoder(os.Stdout).Encode(result); err != nil {
		return nil, err
	}
	if err := waitFile(release, ReleaseTimeout); err != nil {
		return nil, err
	}
	return nil, nil
}

// reuseAddr lets a socket bind a port another socket used a moment ago.
func reuseAddr(network, address string, c syscall.RawConn) error {
	return socketOptions("")(network, address, c)
}

// socketOptions sets SO_REUSEADDR, and SO_BINDTODEVICE when dev is set: an
// app choosing its interface itself, as `curl --interface eth-b` does.
func socketOptions(dev string) func(network, address string, c syscall.RawConn) error {
	return func(_, _ string, c syscall.RawConn) error {
		var serr error
		err := c.Control(func(fd uintptr) {
			serr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1)
			if serr == nil && dev != "" {
				serr = syscall.SetsockoptString(int(fd), syscall.SOL_SOCKET, syscall.SO_BINDTODEVICE, dev)
			}
		})
		if err != nil {
			return err
		}
		return serr
	}
}

func tally(m map[string]int, key string) {
	if key != "" {
		m[key]++
	}
}
