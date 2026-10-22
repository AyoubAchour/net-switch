//go:build windows

package wintun

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sort"
	"sync"
	"sync/atomic"
	"testing"
	"unsafe"

	"gvisor.dev/gvisor/pkg/tcpip/checksum"
)

const integrityTransferSize = 64 << 20
const integrityConnectionLimit = 16 // two warm-ups + eight measured streams

var integrityTransferID atomic.Uint64

// Retain the original pattern, XORed with an eight-byte transfer/stream ID
// and an eight-byte block offset. Substitution and the old pattern's 64256-byte
// periodicity can no longer masquerade as intact data. This is not cryptography.
func integrityByte(id uint64, offset int64) byte {
	v := id
	if offset&15 >= 8 {
		v = uint64(offset) / 16
	}
	return byte(offset*13+offset/251) ^ byte(v>>uint((offset&7)*8))
}

type integrityRecord struct {
	Number      uint64 `json:"number"`
	Stage       string `json:"stage"`
	Seq         uint32 `json:"seq"`
	Ack         uint32 `json:"ack"`
	Flags       byte   `json:"flags"`
	Length      int    `json:"length"`
	Offset      int64  `json:"offset"`
	IPChecksum  bool   `json:"ip_checksum"`
	TCPChecksum bool   `json:"tcp_checksum"`
}

type integrityFailure struct {
	Reason   string            `json:"reason"`
	Offset   int64             `json:"offset"`
	Expected string            `json:"expected,omitempty"`
	Actual   string            `json:"actual,omitempty"`
	Packet   integrityRecord   `json:"packet"`
	Recent   []integrityRecord `json:"recent"`
}

type integrityCoverage struct {
	Records uint64 `json:"records"`
	Bytes   uint64 `json:"bytes"`
}

type integrityConnection struct {
	Tuple            string                       `json:"tuple"`
	Server           string                       `json:"server"`
	ID               uint64                       `json:"payload_id"`
	Transfer         string                       `json:"transfer"`
	ClientISN        uint32                       `json:"client_isn"`
	ServerISN        uint32                       `json:"server_isn"`
	ServerKnown      bool                         `json:"server_isn_known"`
	Failures         map[string]integrityFailure  `json:"first_failures"`
	Coverage         map[string]integrityCoverage `json:"coverage"`
	HostExpectedHash string                       `json:"host_expected_sha256,omitempty"`
	HostActualHash   string                       `json:"host_actual_sha256,omitempty"`
	recent           [64]integrityRecord
	records          uint64
	emit             func(string, integrityFailure)
}

type integrityDiagnostic struct {
	mu          sync.Mutex
	connections []*integrityConnection
	// Unknown/malformed/ambiguous packets make the diagnostic incomplete,
	// never an assertion that an unobserved boundary was clean.
	issues         map[string]string
	ignoredControl map[string]uint64
	number         uint64
	emit           func(*integrityConnection, string, integrityFailure)
}

func newIntegrityDiagnostic() *integrityDiagnostic {
	return &integrityDiagnostic{issues: make(map[string]string), ignoredControl: make(map[string]uint64)}
}

func (d *integrityDiagnostic) issue(stage, reason string) {
	if _, exists := d.issues[stage]; !exists {
		d.issues[stage] = reason
	}
}

func (c *integrityConnection) history() []integrityRecord {
	n := min(c.records, 64)
	result := make([]integrityRecord, 0, n)
	for i := c.records - n; i < c.records; i++ {
		result = append(result, c.recent[i%64])
	}
	return result
}

func (c *integrityConnection) failure(stage, reason string, offset int64, expected, actual []byte, record integrityRecord) {
	if _, exists := c.Failures[stage]; exists {
		return
	}
	c.Failures[stage] = integrityFailure{Reason: reason, Offset: offset,
		Expected: hex.EncodeToString(expected[:min(16, len(expected))]),
		Actual:   hex.EncodeToString(actual[:min(16, len(actual))]), Packet: record, Recent: c.history()}
	if c.emit != nil {
		c.emit(stage, c.Failures[stage])
	}
}

func (c *integrityConnection) check(stage string, data []byte, offset int64, record integrityRecord) {
	v := c.Coverage[stage]
	v.Records++
	v.Bytes += uint64(len(data))
	c.Coverage[stage] = v
	if len(data) == 0 {
		return
	}
	if c.ID == 0 || offset < 0 || offset+int64(len(data)) > integrityTransferSize {
		c.failure(stage, "unbound identity or offset outside transfer", offset, nil, data, record)
		return
	}
	for i, b := range data {
		if b != integrityByte(c.ID, offset+int64(i)) {
			var expected [16]byte
			for j := range expected {
				expected[j] = integrityByte(c.ID, offset+int64(i+j))
			}
			c.failure(stage, "payload mismatch", offset+int64(i), expected[:], data[i:], record)
			return
		}
	}
}

type integrityPacket struct {
	client string
	out    bool
	data   []byte
	record integrityRecord
}

func parseIntegrityPacket(p []byte) (integrityPacket, error) {
	var result integrityPacket
	if len(p) < 20 || p[0]>>4 != 4 || p[9] != 6 {
		return result, nil // unrelated IPv6 discovery / UDP
	}
	iplen := int(p[0]&15) * 4
	if iplen < 20 || len(p) < iplen+20 || int(binary.BigEndian.Uint16(p[2:])) != len(p) || binary.BigEndian.Uint16(p[6:])&0x3fff != 0 {
		return result, fmt.Errorf("malformed or fragmented IPv4 TCP packet: length=%d", len(p))
	}
	tcp := p[iplen:]
	tcplen := int(tcp[12]>>4) * 4
	if tcplen < 20 || tcplen > len(tcp) {
		return result, fmt.Errorf("invalid TCP header length %d", tcplen)
	}
	src, dst := netip.AddrFrom4([4]byte(p[12:16])), netip.AddrFrom4([4]byte(p[16:20]))
	sp, dp := binary.BigEndian.Uint16(tcp), binary.BigEndian.Uint16(tcp[2:])
	client, server := netip.MustParseAddr("198.19.240.1"), netip.MustParseAddr("198.19.240.2")
	switch {
	case src == client && dst == server && dp == 9002:
		result.client = netip.AddrPortFrom(src, sp).String()
	case src == server && dst == client && sp == 9002:
		result.client, result.out = netip.AddrPortFrom(dst, dp).String(), true
	default:
		return result, fmt.Errorf("unexpected TCP tuple %s:%d -> %s:%d", src, sp, dst, dp)
	}
	var pseudo [12]byte
	copy(pseudo[:8], p[12:20])
	pseudo[9] = 6
	binary.BigEndian.PutUint16(pseudo[10:], uint16(len(tcp)))
	result.data = tcp[tcplen:]
	result.record = integrityRecord{Seq: binary.BigEndian.Uint32(tcp[4:]), Ack: binary.BigEndian.Uint32(tcp[8:]),
		Flags: tcp[13], Length: len(result.data), Offset: -1,
		IPChecksum:  checksum.Checksum(p[:iplen], 0) == 65535,
		TCPChecksum: checksum.Checksum(tcp, checksum.Checksum(pseudo[:], 0)) == 65535}
	return result, nil
}

// All offsets are within one 64 MiB transfer (< 2^31). Modular subtraction
// handles ISN wrap, retransmissions and out-of-order segments without treating
// arrival order as stream order. SYN consumes one sequence number, FIN no data.
func integrityOffset(seq, isn uint32, syn bool) int64 {
	if syn {
		seq++
	}
	return int64(int32(seq - (isn + 1)))
}

func (d *integrityDiagnostic) connection(p integrityPacket, stage string) *integrityConnection {
	syn := p.record.Flags&2 != 0
	for _, c := range d.connections {
		if c.Tuple == p.client && syn && !p.out && c.ClientISN == p.record.Seq {
			return c // repeated SYN, including the same packet at another boundary
		}
	}
	if syn && !p.out {
		if len(d.connections) == integrityConnectionLimit {
			d.issue(stage, "connection evidence limit exceeded")
			return nil
		}
		c := &integrityConnection{Tuple: p.client, Server: "198.19.240.2:9002", ClientISN: p.record.Seq,
			Failures: make(map[string]integrityFailure), Coverage: make(map[string]integrityCoverage)}
		if d.emit != nil {
			c.emit = func(stage string, f integrityFailure) { d.emit(c, stage, f) }
		}
		d.connections = append(d.connections, c)
		return c
	}
	var found *integrityConnection
	for _, c := range d.connections {
		if c.Tuple != p.client {
			continue
		}
		if syn && p.out {
			if p.record.Ack != c.ClientISN+1 {
				continue
			}
			if c.ServerKnown && c.ServerISN != p.record.Seq {
				d.issue(stage, "server ISN changed for same client SYN")
				return nil
			}
			c.ServerISN, c.ServerKnown = p.record.Seq, true
		} else {
			isn := c.ClientISN
			if p.out {
				if !c.ServerKnown {
					continue
				}
				isn = c.ServerISN
			}
			offset := integrityOffset(p.record.Seq, isn, false)
			if offset < -1 || offset > integrityTransferSize+1 {
				continue
			}
		}
		if found != nil {
			d.issue(stage, "ambiguous reused tuple/sequence range")
			return nil
		}
		found = c
	}
	if found == nil {
		if len(p.data) == 0 {
			// A new fixture can see a delayed ACK/RST from the previous TCP
			// stack. It has no payload to validate and is not a new stream.
			d.ignoredControl[stage]++
		} else {
			d.issue(stage, "missing SYN identity for "+p.client)
		}
	}
	return found
}

func (d *integrityDiagnostic) packetLocked(stage string, data []byte) (*integrityConnection, integrityRecord) {
	p, err := parseIntegrityPacket(data)
	if err != nil {
		d.issue(stage, err.Error())
		return nil, integrityRecord{}
	}
	if p.client == "" {
		return nil, integrityRecord{}
	}
	c := d.connection(p, stage)
	if c == nil {
		return nil, integrityRecord{}
	}
	isn := c.ClientISN
	if p.out {
		isn = c.ServerISN
	}
	d.number++
	r := p.record
	r.Number, r.Stage, r.Offset = d.number, stage, integrityOffset(r.Seq, isn, r.Flags&2 != 0)
	c.recent[c.records%64] = r
	c.records++
	c.check(stage, p.data, r.Offset, r)
	return c, r
}

func (d *integrityDiagnostic) packet(stage string, data []byte) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.packetLocked(stage, data)
}

// native is still owned: receive before release/head publication, send before
// send/tail publication. Retain only scalar metadata and bounded hex strings.
func (d *integrityDiagnostic) native(stage string, native, copied []byte) {
	d.mu.Lock()
	defer d.mu.Unlock()
	c, r := d.packetLocked(stage, native)
	cc, cr := d.packetLocked(stage+"_copy", copied)
	if !bytes.Equal(native, copied) {
		if c == nil {
			c, r = cc, cr
		}
		if c == nil {
			d.issue(stage, "native/copy mismatch without parseable identity")
			return
		}
		i := 0
		for i < min(len(native), len(copied)) && native[i] == copied[i] {
			i++
		}
		want, got := native, copied
		if stage == "dll_send" || stage == "ours_send" {
			want, got = copied, native // send copies from Go source into native memory
		}
		c.failure(stage+"_copy_equal", "copy differs at packet byte (not stream offset)", int64(i), want[i:], got[i:], r)
	}
}

func (d *integrityDiagnostic) nativeAddress(stage string, address uintptr, copied []byte) {
	// DLL returns native memory, never a Go heap pointer. Same reinterpretation
	// as allocateRings; do not manufacture a Go-heap pointer by arithmetic.
	p := *(*unsafe.Pointer)(unsafe.Pointer(&address))
	d.native(stage, unsafe.Slice((*byte)(p), len(copied)), copied)
}

func (d *integrityDiagnostic) bind(local string, id uint64, transfer string) *integrityConnection {
	d.mu.Lock()
	defer d.mu.Unlock()
	for i := len(d.connections) - 1; i >= 0; i-- {
		c := d.connections[i]
		if c.Tuple == local && c.ID == 0 {
			c.ID, c.Transfer = id, transfer
			return c
		}
	}
	d.issue("host_bind", "no unbound handshake for "+local)
	return nil
}

func (d *integrityDiagnostic) stream(stage, local string, offset int64, data []byte) {
	d.readStream(stage, local, nil, offset, data)
}

func (d *integrityDiagnostic) readStream(stage, local string, bound *integrityConnection, offset int64, data []byte) *integrityConnection {
	d.mu.Lock()
	defer d.mu.Unlock()
	if bound != nil {
		bound.check(stage, data, offset, integrityRecord{})
		return bound
	}
	for i := len(d.connections) - 1; i >= 0; i-- {
		c := d.connections[i]
		if c.Tuple == local && c.ID != 0 {
			c.check(stage, data, offset, integrityRecord{})
			return c
		}
	}
	d.issue(stage, "no bound stream for "+local)
	return nil
}

type integrityReader struct {
	reader       io.Reader
	d            *integrityDiagnostic
	stage, local string
	offset       int64
	connection   *integrityConnection
}

func (r *integrityReader) Read(p []byte) (int, error) {
	n, err := r.reader.Read(p)
	if n != 0 {
		r.connection = r.d.readStream(r.stage, r.local, r.connection, r.offset, p[:n])
		r.offset += int64(n)
	}
	return n, err
}

func (d *integrityDiagnostic) echo(c net.Conn) (int64, error) {
	return io.Copy(c, &integrityReader{reader: c, d: d, stage: "echo_read", local: c.RemoteAddr().String()})
}

func (d *integrityDiagnostic) hashes(c *integrityConnection, expected, actual []byte) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if c != nil {
		c.HostExpectedHash, c.HostActualHash = hex.EncodeToString(expected), hex.EncodeToString(actual)
	}
}

func (d *integrityDiagnostic) complete(c *integrityConnection) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if c == nil {
		d.issue("coverage", "completed transfer without identity")
		return
	}
	mode := "dll"
	if c.Coverage["ours_receive"].Records != 0 {
		mode = "ours"
	}
	for _, stage := range []string{mode + "_receive", mode + "_receive_copy", "stack_ingress", "echo_read", "stack_output", mode + "_send", mode + "_send_copy", "host_receive"} {
		v := c.Coverage[stage]
		if v.Bytes < integrityTransferSize || ((stage == "echo_read" || stage == "host_receive") && v.Bytes != integrityTransferSize) {
			c.failure(stage, "incomplete boundary coverage", int64(v.Bytes), nil, nil, integrityRecord{})
		}
	}
	if !c.ServerKnown || c.HostExpectedHash == "" || c.HostActualHash != c.HostExpectedHash {
		c.failure("host_hash", "missing handshake/hash or host hash mismatch", -1, nil, nil, integrityRecord{})
	}
}

func (d *integrityDiagnostic) err() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if len(d.issues) != 0 {
		return fmt.Errorf("integrity diagnostic incomplete: %v", d.issues)
	}
	for _, c := range d.connections {
		if len(c.Failures) != 0 {
			return fmt.Errorf("integrity boundary failure: %s payload_id=%d", c.Tuple, c.ID)
		}
	}
	return nil
}

// Emit after pumps have joined, so no caller retains a mutable report object.
func (d *integrityDiagnostic) report(t *testing.T) {
	d.mu.Lock()
	defer d.mu.Unlock()
	sort.Slice(d.connections, func(i, j int) bool { return d.connections[i].ID < d.connections[j].ID })
	for _, c := range d.connections {
		// Keep every JSON line bounded too: histories get their own records.
		failures := c.Failures
		c.Failures = nil
		report(t, map[string]any{"test": "tcp_integrity", "connection": c})
		c.Failures = failures
		stages := make([]string, 0, len(failures))
		for stage := range failures {
			stages = append(stages, stage)
		}
		sort.Strings(stages)
		for _, stage := range stages {
			if c.emit == nil {
				reportIntegrityFailure(t, c, stage, failures[stage])
			}
		}
		if len(failures) != 0 || len(d.issues) != 0 {
			for _, r := range c.history() {
				report(t, map[string]any{"test": "tcp_integrity_last64", "payload_id": c.ID, "packet": r})
			}
		}
	}
	if len(d.issues) != 0 {
		report(t, map[string]any{"test": "tcp_integrity_incomplete", "issues": d.issues})
	}
	if len(d.ignoredControl) != 0 {
		report(t, map[string]any{"test": "tcp_integrity_unmatched_control", "counts": d.ignoredControl})
	}
}

func reportIntegrityFailure(t *testing.T, c *integrityConnection, stage string, f integrityFailure) {
	// Emit at first detection, while the packet is still owned. Even a later
	// deadlock/test timeout cannot erase the first bad boundary or its history.
	history := f.Recent
	f.Recent = nil
	report(t, map[string]any{"test": "tcp_integrity_first_failure", "tuple": c.Tuple, "server": c.Server, "payload_id": c.ID, "stage": stage, "failure": f})
	for _, r := range history {
		report(t, map[string]any{"test": "tcp_integrity_history", "payload_id": c.ID, "failure_stage": stage, "packet": r})
	}
}
