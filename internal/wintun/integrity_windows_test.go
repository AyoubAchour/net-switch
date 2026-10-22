//go:build windows

package wintun

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
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

var errDiagnosticIncomplete = errors.New("diagnostic incomplete")
var errPayloadIntegrity = errors.New("payload integrity failure")

func integrityVerdict(err error) string {
	switch {
	case errors.Is(err, errPayloadIntegrity):
		return "integrity_failure"
	case errors.Is(err, errDiagnosticIncomplete):
		return "diagnostic_incomplete"
	case err != nil:
		return "transfer_error"
	default:
		return "ok"
	}
}

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
	Number          uint64 `json:"number"`
	Stage           string `json:"stage"`
	Seq             uint32 `json:"seq"`
	Ack             uint32 `json:"ack"`
	Flags           byte   `json:"flags"`
	Length          int    `json:"length"`
	Offset          int64  `json:"offset"`
	IPChecksum      bool   `json:"ip_checksum"`
	TCPChecksum     bool   `json:"tcp_checksum"`
	ChecksumChecked bool   `json:"checksum_checked"`
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
	ClientKnown      bool                         `json:"client_isn_known"`
	ClientSource     string                       `json:"client_sequence_source,omitempty"`
	ServerSource     string                       `json:"server_sequence_source,omitempty"`
	ServerISN        uint32                       `json:"server_isn"`
	ServerKnown      bool                         `json:"server_isn_known"`
	Failures         map[string]integrityFailure  `json:"first_failures"`
	Coverage         map[string]integrityCoverage `json:"coverage"`
	Incomplete       map[string]string            `json:"incomplete,omitempty"`
	HostExpectedHash string                       `json:"host_expected_sha256,omitempty"`
	HostActualHash   string                       `json:"host_actual_sha256,omitempty"`
	recent           [64]integrityRecord
	records          uint64
	emit             func(string, integrityFailure)
	reference        []byte // Independent immutable oracle; never given to the sender.
}

type integrityDiagnostic struct {
	mu          sync.Mutex
	connections []*integrityConnection
	// Unknown/malformed/ambiguous packets make the diagnostic incomplete,
	// never an assertion that an unobserved boundary was clean.
	issues              map[string]string
	ignoredControl      map[string]uint64
	number              uint64
	emit                func(*integrityConnection, string, integrityFailure)
	boundary            string // Empty means all (pure fixtures); runtime defaults to receive.
	unregisteredPayload map[string]uint64
}

func newIntegrityDiagnostic() *integrityDiagnostic {
	return &integrityDiagnostic{issues: make(map[string]string), ignoredControl: make(map[string]uint64), unregisteredPayload: make(map[string]uint64)}
}

func (d *integrityDiagnostic) selected(stage string) bool {
	if d.boundary == "" || d.boundary == "all" {
		return true
	}
	switch d.boundary {
	case "receive":
		return stage == "ours_receive" || stage == "dll_receive"
	case "send":
		return stage == "ours_send" || stage == "dll_send"
	case "ingress":
		return stage == "stack_ingress"
	case "output":
		return stage == "stack_output"
	case "echo":
		return stage == "echo_read"
	case "host":
		return stage == "host_receive"
	}
	return false
}

func (c *integrityConnection) incomplete(stage, reason string) {
	if c.Incomplete == nil {
		c.Incomplete = make(map[string]string)
	}
	if _, exists := c.Incomplete[stage]; !exists {
		c.Incomplete[stage] = reason
	}
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

func (c *integrityConnection) check(stage string, data []byte, offset int64, record integrityRecord, wire ...[]byte) {
	v := c.Coverage[stage]
	v.Records++
	v.Bytes += uint64(len(data))
	c.Coverage[stage] = v
	if len(data) == 0 {
		return
	}
	if c.ID == 0 || offset < 0 || offset+int64(len(data)) > integrityTransferSize {
		c.incomplete(stage, "unbound identity or offset outside transfer")
		return
	}
	// The sender gets a separate allocation. SIMD equality avoids regenerating
	// the pattern for every byte at every boundary while holding the mutex.
	if c.reference != nil && offset+int64(len(data)) <= int64(len(c.reference)) && bytes.Equal(data, c.reference[offset:offset+int64(len(data))]) {
		return
	}
	for i, b := range data {
		if b != integrityByte(c.ID, offset+int64(i)) {
			if len(wire) != 0 {
				record = integrityChecksums(record, wire[0])
			}
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

func integrityChecksums(r integrityRecord, p []byte) integrityRecord {
	if len(p) < 20 || p[0]>>4 != 4 {
		return r
	}
	h := int(p[0]&15) * 4
	if h < 20 || h > len(p) {
		return r
	}
	var pseudo [12]byte
	copy(pseudo[:8], p[12:20])
	pseudo[9] = 6
	binary.BigEndian.PutUint16(pseudo[10:], uint16(len(p)-h))
	r.ChecksumChecked = true
	r.IPChecksum = checksum.Checksum(p[:h], 0) == 65535
	r.TCPChecksum = checksum.Checksum(p[h:], checksum.Checksum(pseudo[:], 0)) == 65535
	return r
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
	result.data = tcp[tcplen:]
	result.record = integrityRecord{Seq: binary.BigEndian.Uint32(tcp[4:]), Ack: binary.BigEndian.Uint32(tcp[8:]),
		Flags: tcp[13], Length: len(result.data), Offset: -1}
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

func (d *integrityDiagnostic) newConnection(local string) *integrityConnection {
	if len(d.connections) == integrityConnectionLimit {
		// Keep bound transfers and their evidence. Unbound late SYNs are only
		// handshake hints and must not consume the active-connection budget.
		removed := false
		for i, c := range d.connections {
			if c.ID == 0 {
				d.connections = append(d.connections[:i], d.connections[i+1:]...)
				removed = true
				break
			}
		}
		if !removed {
			d.issue("identity", "bound connection evidence limit exceeded")
			return nil
		}
	}
	c := &integrityConnection{Tuple: local, Server: "198.19.240.2:9002",
		Failures: make(map[string]integrityFailure), Coverage: make(map[string]integrityCoverage)}
	if d.emit != nil {
		c.emit = func(stage string, f integrityFailure) { d.emit(c, stage, f) }
	}
	d.connections = append(d.connections, c)
	return c
}

func recoverIntegritySequence(c *integrityConnection, p integrityPacket) bool {
	// No guessed zero offset: recover only from a unique 32-byte match in the
	// independently generated oracle registered by the host before its Write.
	// This cold path handles a missed SYN or attaching after a handshake.
	for start := 0; start+32 <= len(p.data) && start <= 64; start += 32 {
		fragment := p.data[start : start+32]
		at := bytes.Index(c.reference, fragment)
		if at < start || bytes.Index(c.reference[at+1:], fragment) >= 0 {
			continue
		}
		offset := at - start
		isn := p.record.Seq - uint32(offset) - 1
		if p.out {
			c.ServerISN, c.ServerKnown, c.ServerSource = isn, true, "payload_oracle"
		} else {
			c.ClientISN, c.ClientKnown, c.ClientSource = isn, true, "payload_oracle"
		}
		return true
	}
	return false
}

func (d *integrityDiagnostic) connection(p integrityPacket, stage string) *integrityConnection {
	syn := p.record.Flags&2 != 0
	for _, c := range d.connections {
		if c.Tuple == p.client && syn && !p.out && c.ClientKnown && c.ClientISN == p.record.Seq {
			return c // repeated SYN, including the same packet at another boundary
		}
	}
	if syn && !p.out {
		for _, c := range d.connections {
			if c.Tuple == p.client && c.ID != 0 && !c.ClientKnown {
				c.ClientISN, c.ClientKnown, c.ClientSource = p.record.Seq, true, "late_syn"
				return c
			}
		}
		c := d.newConnection(p.client)
		if c != nil {
			c.ClientISN, c.ClientKnown, c.ClientSource = p.record.Seq, true, "syn"
		}
		return c
	}
	if syn && p.out {
		for _, c := range d.connections {
			if c.Tuple == p.client && c.ID != 0 && !c.ClientKnown {
				c.ClientISN, c.ClientKnown, c.ClientSource = p.record.Ack-1, true, "late_synack_ack"
				c.ServerISN, c.ServerKnown, c.ServerSource = p.record.Seq, true, "late_synack"
				return c
			}
			if c.Tuple == p.client && c.ClientKnown && p.record.Ack == c.ClientISN+1 {
				if c.ServerKnown && c.ServerISN != p.record.Seq {
					d.issue(stage, "server ISN changed for same client SYN")
					return nil
				}
				c.ServerISN, c.ServerKnown, c.ServerSource = p.record.Seq, true, "synack"
				return c
			}
		}
		c := d.newConnection(p.client)
		if c != nil {
			c.ClientISN, c.ClientKnown, c.ClientSource = p.record.Ack-1, true, "synack_ack"
			c.ServerISN, c.ServerKnown, c.ServerSource = p.record.Seq, true, "synack"
		}
		return c
	}
	var found *integrityConnection
	for _, c := range d.connections {
		if c.Tuple != p.client {
			continue
		}
		known, isn := c.ClientKnown, c.ClientISN
		if p.out {
			known, isn = c.ServerKnown, c.ServerISN
		}
		if !known {
			if !recoverIntegritySequence(c, p) {
				continue
			}
			if p.out {
				isn = c.ServerISN
			} else {
				isn = c.ClientISN
			}
		}
		offset := integrityOffset(p.record.Seq, isn, false)
		if offset < -1 || offset > integrityTransferSize+1 {
			continue
		}
		if found != nil {
			if found.ClientKnown && c.ClientKnown && found.ClientISN == c.ClientISN && found.ServerKnown && c.ServerKnown && found.ServerISN == c.ServerISN {
				if c.ID != 0 {
					found = c
				}
				continue
			}
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
			// The host binds each tested stream before writing any payload.
			// Foreign/retired tuples (including prior fixtures) are not missing
			// evidence for an active transfer. Preserve a count, not a false failure.
			bound := false
			for _, c := range d.connections {
				if c.Tuple == p.client && c.ID != 0 {
					bound = true
					break
				}
			}
			if bound {
				d.issue(stage, fmt.Sprintf("unresolved sequence for bound stream %s: seq=%d ack=%d flags=%02x payload=%d", p.client, p.record.Seq, p.record.Ack, p.record.Flags, len(p.data)))
			} else {
				d.unregisteredPayload[stage]++
			}
		}
	}
	if found != nil && found.ID == 0 && len(p.data) != 0 {
		d.unregisteredPayload[stage]++
		return nil
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
	if c.ID == 0 && len(p.data) != 0 {
		d.unregisteredPayload[stage]++
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
	c.check(stage, p.data, r.Offset, r, data)
	return c, r
}

func (d *integrityDiagnostic) packet(stage string, data []byte) {
	if !d.selected(stage) && !integritySYN(data) {
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	d.packetLocked(stage, data)
}

// native is still owned: receive before release/head publication, send before
// send/tail publication. Retain only scalar metadata and bounded hex strings.
func (d *integrityDiagnostic) native(stage string, native, copied []byte) {
	if !d.selected(stage) {
		if integritySYN(native) {
			d.packet(stage, native)
		}
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	c, r := d.packetLocked(stage, native)
	if bytes.Equal(native, copied) {
		if c != nil && d.selected(stage) {
			v := c.Coverage[stage+"_copy"]
			v.Records++
			v.Bytes += uint64(r.Length)
			c.Coverage[stage+"_copy"] = v
		}
	} else {
		cc, cr := d.packetLocked(stage+"_copy", copied)
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
		r = integrityChecksums(r, got)
		c.failure(stage+"_copy_equal", "copy differs at packet byte (not stream offset)", int64(i), want[i:], got[i:], r)
	}
}

func (d *integrityDiagnostic) nativeAddress(stage string, address uintptr, copied []byte) {
	// DLL returns native memory, never a Go heap pointer. Same reinterpretation
	// as allocateRings; do not manufacture a Go-heap pointer by arithmetic.
	p := *(*unsafe.Pointer)(unsafe.Pointer(&address))
	d.native(stage, unsafe.Slice((*byte)(p), len(copied)), copied)
}

func (d *integrityDiagnostic) bind(local string, id uint64, transfer string, reference ...[]byte) *integrityConnection {
	d.mu.Lock()
	defer d.mu.Unlock()
	var best *integrityConnection
	for i := len(d.connections) - 1; i >= 0; i-- {
		c := d.connections[i]
		if c.Tuple == local && c.ID == 0 {
			if best == nil || (!best.ServerKnown && c.ServerKnown) {
				best = c
			}
		}
	}
	if best == nil {
		best = d.newConnection(local)
	}
	if best != nil {
		best.ID, best.Transfer = id, transfer
		if len(reference) != 0 {
			best.reference = reference[0]
		}
	}
	return best
}

func integritySYN(p []byte) bool {
	if len(p) < 40 || p[0]>>4 != 4 || p[9] != 6 {
		return false
	}
	h := int(p[0]&15) * 4
	return h >= 20 && len(p) >= h+20 && p[h+13]&2 != 0
}

func (d *integrityDiagnostic) stream(stage, local string, offset int64, data []byte) {
	d.readStream(stage, local, nil, offset, data)
}

func (d *integrityDiagnostic) readStream(stage, local string, bound *integrityConnection, offset int64, data []byte) *integrityConnection {
	if !d.selected(stage) {
		return bound
	}
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
	reader        io.Reader
	d             *integrityDiagnostic
	stage, local  string
	offset        int64
	connection    *integrityConnection
	fastReference []byte
	bad           bool
	reads         int64
}

func (r *integrityReader) Read(p []byte) (int, error) {
	n, err := r.reader.Read(p)
	if n != 0 {
		r.reads++
		if r.fastReference != nil {
			// This reader alone owns its ordered stream position. No global
			// mutex, pattern generation or per-read map writes on a clean read.
			end := r.offset + int64(n)
			if !r.bad && (end > int64(len(r.fastReference)) || !bytes.Equal(p[:n], r.fastReference[r.offset:end])) {
				r.d.mu.Lock()
				r.connection.check(r.stage, p[:n], r.offset, integrityRecord{})
				r.d.mu.Unlock()
				r.bad = true
			}
		} else {
			r.connection = r.d.readStream(r.stage, r.local, r.connection, r.offset, p[:n])
		}
		r.offset += int64(n)
	}
	return n, err
}

func (d *integrityDiagnostic) echo(c net.Conn) (int64, error) {
	return io.Copy(c, &integrityReader{reader: c, d: d, stage: "echo_read", local: c.RemoteAddr().String()})
}

func (d *integrityDiagnostic) hashes(c *integrityConnection, expected, actual []byte, observed ...int64) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if c != nil {
		c.HostExpectedHash, c.HostActualHash = hex.EncodeToString(expected), hex.EncodeToString(actual)
		if len(observed) == 2 {
			c.Coverage["host_receive"] = integrityCoverage{Bytes: uint64(observed[0]), Records: uint64(observed[1])}
		}
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
	if c.Coverage["ours_receive"].Records != 0 || c.Coverage["ours_send"].Records != 0 {
		mode = "ours"
	}
	for _, stage := range []string{mode + "_receive", "stack_ingress", "echo_read", "stack_output", mode + "_send", "host_receive"} {
		if !d.selected(stage) {
			continue
		}
		v := c.Coverage[stage]
		if v.Bytes < integrityTransferSize || ((stage == "echo_read" || stage == "host_receive") && v.Bytes != integrityTransferSize) {
			c.incomplete(stage, fmt.Sprintf("incomplete selected boundary coverage: %d bytes", v.Bytes))
		}
	}
	if c.HostExpectedHash == "" || c.HostActualHash == "" {
		c.incomplete("host_hash", "missing host hash")
	} else if c.HostActualHash != c.HostExpectedHash {
		c.failure("host_hash", "host hash mismatch", -1, nil, nil, integrityRecord{})
	}
	// Late retransmissions can still use the deterministic fallback; do not
	// retain 64 MiB per finished warm-up for the entire fixture.
	c.reference = nil
}

func (d *integrityDiagnostic) err() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	var result error
	if len(d.issues) != 0 {
		result = fmt.Errorf("%w: %v", errDiagnosticIncomplete, d.issues)
	}
	for _, c := range d.connections {
		if len(c.Failures) != 0 {
			result = errors.Join(result, fmt.Errorf("%w: %s payload_id=%d", errPayloadIntegrity, c.Tuple, c.ID))
		}
		if len(c.Incomplete) != 0 {
			result = errors.Join(result, fmt.Errorf("%w: %s payload_id=%d %v", errDiagnosticIncomplete, c.Tuple, c.ID, c.Incomplete))
		}
	}
	return result
}

// Emit after pumps have joined, so no caller retains a mutable report object.
func (d *integrityDiagnostic) report(t *testing.T) {
	d.mu.Lock()
	defer d.mu.Unlock()
	sort.Slice(d.connections, func(i, j int) bool { return d.connections[i].ID < d.connections[j].ID })
	for _, c := range d.connections {
		if c.ID == 0 && len(c.Failures) == 0 && len(c.Incomplete) == 0 {
			continue
		} // unbound SYN hints are not checked transfers
		// Keep every JSON line bounded too: histories get their own records.
		failures := c.Failures
		c.Failures = nil
		verdict := "ok"
		if len(c.Incomplete) != 0 {
			verdict = "diagnostic_incomplete"
		}
		if len(failures) != 0 {
			verdict = "integrity_failure"
		}
		scope := "selected_boundary_plus_host"
		if d.boundary == "" || d.boundary == "all" {
			scope = "all_boundaries"
		}
		report(t, map[string]any{"test": "tcp_integrity", "connection": c, "boundary": d.boundary, "verdict": verdict, "coverage_scope": scope})
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
		report(t, map[string]any{"test": "tcp_integrity_incomplete", "verdict": "diagnostic_incomplete", "issues": d.issues})
	}
	if len(d.ignoredControl) != 0 {
		report(t, map[string]any{"test": "tcp_integrity_unmatched_control", "counts": d.ignoredControl})
	}
	if len(d.unregisteredPayload) != 0 {
		report(t, map[string]any{"test": "tcp_integrity_unregistered_payload", "counts": d.unregisteredPayload})
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
