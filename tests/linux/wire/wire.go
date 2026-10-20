// Package wire holds the small protocols the fake internet speaks to the test
// apps: ports, line formats, a STUN Binding subset (RFC 5389), a DNS subset
// and deterministic bulk data. It has no I/O of its own, so it is unit-tested
// on every platform.
package wire

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"math/rand/v2"
	"net/netip"
	"strings"
)

// Ports served by the fake internet. Every service reports the source address
// it saw, which names the line a connection used.
const (
	PortUDPEcho  = 7001 // UDP: replies "<ip>:<port> <payload>"
	PortStream   = 7002 // TCP: each "ping N" line gets "pong N <ip>"
	PortWhoami   = 7003 // TCP: writes "<ip>\n" and closes
	PortBulk     = 7004 // TCP: "GET n" sends n bytes; "PUT n" + n bytes gets their SHA-256
	PortPoke     = 7005 // UDP: "poke <token>" is answered from another host (see PokeFrom)
	PortPokeSrc  = 7006 // the port the third host answers pokes from
	PortUDPReply = 7007 // UDP: a small request asks for a large, hashed reply
	PortHold     = 7008 // TCP: accepts and holds the connection, sending nothing
	// PortBlackhole: the fake internet drops every TCP packet to this port,
	// so a connection there never gets past its handshake.
	PortBlackhole = 7009
	PortHTTP      = 8080 // HTTP: the body is the source address; /slow?ms=N waits first
	PortDNS       = 53
	PortSTUN1     = 3478
	PortSTUN2     = 3479
	PortProbe     = 443  // TCP on the line-check operators' addresses (1.1.1.1, 8.8.8.8, 9.9.9.9)
	PortQUIC      = 4433 // UDP: the QUIC cases' own server (tests/quicfixture)
)

// EchoReply is the UDP echo answer for a datagram from src.
func EchoReply(src netip.AddrPort, payload []byte) []byte {
	return append([]byte(src.String()+" "), payload...)
}

// ParseEchoReply splits an echo answer into what the server saw and the
// original payload.
func ParseEchoReply(reply []byte) (seen netip.AddrPort, payload []byte, err error) {
	i := bytes.IndexByte(reply, ' ')
	if i < 0 {
		return netip.AddrPort{}, nil, fmt.Errorf("echo reply %q has no space", truncate(reply))
	}
	seen, err = netip.ParseAddrPort(string(reply[:i]))
	if err != nil {
		return netip.AddrPort{}, nil, fmt.Errorf("echo reply %q: %w", truncate(reply), err)
	}
	return seen, reply[i+1:], nil
}

func truncate(b []byte) string {
	if len(b) > 60 {
		return string(b[:60]) + "..."
	}
	return string(b)
}

// Pattern is the deterministic data the bulk service sends for a request of n
// bytes; both sides generate it, so a transfer is checked by hash.
func Pattern(n int64) io.Reader {
	var seed [32]byte
	binary.LittleEndian.PutUint64(seed[:], uint64(n))
	copy(seed[8:], "net-switch linux acceptance")
	return io.LimitReader(rand.NewChaCha8(seed), n)
}

// PatternSHA256 is the hex SHA-256 of Pattern(n).
func PatternSHA256(n int64) string {
	h := sha256.New()
	if _, err := io.Copy(h, Pattern(n)); err != nil {
		panic(err) // a ChaCha8 stream can't fail
	}
	return hex.EncodeToString(h.Sum(nil))
}

// FloodPattern is the endless data a "FLOOD ms" request gets: the server
// sends it as fast as it can for ms milliseconds, then one byte every 100 ms
// until the client closes. The client checks every byte against its own copy.
func FloodPattern() io.Reader { return Pattern(floodLength) }

const floodLength = 1 << 50

// MaxFloodMS bounds a FLOOD request's full-speed part.
const MaxFloodMS = 60_000

// ParseBulkRequest reads "GET n", "PUT n" (bytes) or "FLOOD n" (ms).
func ParseBulkRequest(line string) (verb string, n int64, err error) {
	fields := strings.Fields(line)
	if len(fields) != 2 || (fields[0] != "GET" && fields[0] != "PUT" && fields[0] != "FLOOD") {
		return "", 0, fmt.Errorf("bad bulk request %q", line)
	}
	if _, err := fmt.Sscan(fields[1], &n); err != nil || n < 0 || n > 1<<31 || (fields[0] == "FLOOD" && n > MaxFloodMS) {
		return "", 0, fmt.Errorf("bad bulk size in %q", line)
	}
	return fields[0], n, nil
}
