//go:build windows && wintun_boundaries

package wintun

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/bits"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"

	ns "github.com/AyoubAchour/net-switch/internal/engine/stack"
	"gvisor.dev/gvisor/pkg/buffer"
	gv "gvisor.dev/gvisor/pkg/tcpip/stack"
)

const boundaryFailureLimit = 8
const boundaryHistoryLimit = 64
const boundaryFlowLimit = 16            // two warmups plus eight measured connections
var boundaryFailureNumber atomic.Uint64 // process/run budget, never reset by a fixture

var boundaryStages = [4]string{"ring_ingress", "stack_write", "ring_publish", "echo_read"}

type boundaryIdentity struct {
	Transfer uint64 `json:"transfer"`
	Stream   int    `json:"stream"`
}
type boundaryISN struct{ seq uint32 }
type boundaryRecord struct {
	Stage      string `json:"stage"`
	Seq        uint32 `json:"seq"`
	Flags      byte   `json:"flags"`
	Length     int    `json:"length"`
	Offset     int64  `json:"offset"`
	Retransmit bool   `json:"retransmit_or_overlap"`
	Slot       int64  `json:"slot"`
	Batch      uint64 `json:"batch"`
	Index      int    `json:"batch_index"`
}
type boundarySpan struct{ Start, End int64 }
type boundaryState struct {
	mu        sync.Mutex
	high      int64
	history   [boundaryHistoryLimit]boundaryRecord
	seen      uint64
	spans     [128]boundarySpan
	spanCount int
	bytes     uint64
}

// Exact interval union, including partial overlaps and retransmissions. A full
// interval table is incomplete evidence, never a claim that coverage is clean.
func (s *boundaryState) cover(start, end int64) bool {
	i := 0
	for i < s.spanCount && s.spans[i].End < start {
		i++
	}
	j := i
	for j < s.spanCount && s.spans[j].Start <= end {
		start = min(start, s.spans[j].Start)
		end = max(end, s.spans[j].End)
		j++
	}
	if i == j && s.spanCount == len(s.spans) {
		return false
	}
	copy(s.spans[i+1:], s.spans[j:s.spanCount])
	s.spanCount += 1 - (j - i)
	s.spans[i] = boundarySpan{start, end}
	return true
}
func (s *boundaryState) recent() []boundaryRecord {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := min(s.seen, uint64(len(s.history)))
	out := make([]boundaryRecord, 0, n)
	for i := s.seen - n; i < s.seen; i++ {
		out = append(out, s.history[i%uint64(len(s.history))])
	}
	return out
}

type boundaryFlow struct {
	port                      uint16
	identity                  atomic.Pointer[boundaryIdentity]
	client, server            atomic.Pointer[boundaryISN]
	state                     [4]boundaryState
	hostReported, hostEmitted atomic.Bool
}
type boundaryCapture struct {
	t                  *testing.T
	mode               string
	flows              [65536]atomic.Pointer[boundaryFlow]
	failed, incomplete atomic.Bool
	issueOnce          sync.Once
	listMu             sync.Mutex
	list               []*boundaryFlow
	budget             *atomic.Uint64
	emit               func(map[string]any)
	fixture            *fixture
	ringOnce           sync.Once
}

func (d *boundaryCapture) number() uint64 {
	if d.budget != nil {
		return d.budget.Add(1)
	}
	return boundaryFailureNumber.Add(1)
}
func (d *boundaryCapture) report(value map[string]any) {
	if d.emit != nil {
		d.emit(value)
	} else {
		report(d.t, value)
	}
}

func attachWordBoundaries(t *testing.T, f *fixture) (wordBoundaryCapture, func()) {
	d := &boundaryCapture{t: t, mode: f.mode, fixture: f}
	h := &wordRingObserver{inspect: d.raw}
	if !wordRingHook.CompareAndSwap(nil, h) {
		t.Fatal("word ring observer already installed")
	}
	detach, ok := ns.InstallBoundaryObserver(d.stack)
	if !ok {
		wordRingHook.CompareAndSwap(h, nil)
		t.Fatal("word stack observer already installed")
	}
	return d, func() { detach(); wordRingHook.CompareAndSwap(h, nil) }
}
func observeWordDLL(stage string, p []byte) {
	if h := wordRingHook.Load(); h != nil {
		h.inspect(stage, p, -1, wordRingBatchID.Add(1), 0)
	}
}
func (d *boundaryCapture) issue(reason string) {
	d.incomplete.Store(true)
	d.issueOnce.Do(func() {
		if d.number() <= boundaryFailureLimit {
			d.report(map[string]any{"test": "word_boundary_incomplete", "verdict": "diagnostic_incomplete", "mode": d.mode, "reason": reason})
		}
	})
}
func (d *boundaryCapture) flow(port uint16, create bool) *boundaryFlow {
	if f := d.flows[port].Load(); f != nil {
		return f
	}
	if !create {
		d.issue("test flow observed without SYN")
		return nil
	}
	d.listMu.Lock()
	defer d.listMu.Unlock()
	if f := d.flows[port].Load(); f != nil {
		return f
	}
	if len(d.list) >= boundaryFlowLimit {
		d.issue("flow limit reached")
		return nil
	}
	f := &boundaryFlow{port: port}
	d.list = append(d.list, f)
	d.flows[port].Store(f)
	return f
}
func boundaryPort(local string) (uint16, error) {
	_, port, err := net.SplitHostPort(local)
	if err != nil {
		return 0, err
	}
	n, err := strconv.ParseUint(port, 10, 16)
	return uint16(n), err
}
func (d *boundaryCapture) bind(local string, transfer uint64, stream int) {
	port, err := boundaryPort(local)
	if err != nil {
		d.issue(err.Error())
		return
	}
	f := d.flow(port, false)
	if f == nil {
		return
	}
	if !f.identity.CompareAndSwap(nil, &boundaryIdentity{transfer, stream}) {
		d.issue("tuple reused within fixture")
	}
}

type boundaryPayload struct {
	raw          []byte
	views        buffer.ViewList
	skip, length int
}

func (p boundaryPayload) walk(fn func([]byte) bool) {
	if p.raw != nil {
		fn(p.raw)
		return
	}
	skip, left := p.skip, p.length
	for v := p.views.Front(); v != nil && left > 0; v = v.Next() {
		b := v.AsSlice()
		if skip >= len(b) {
			skip -= len(b)
			continue
		}
		b = b[skip:]
		skip = 0
		b = b[:min(len(b), left)]
		left -= len(b)
		if !fn(b) {
			return
		}
	}
}
func (p boundaryPayload) copyAt(dst []byte, offset int) int {
	n := 0
	p.walk(func(b []byte) bool {
		if offset >= len(b) {
			offset -= len(b)
			return true
		}
		b = b[offset:]
		offset = 0
		n += copy(dst[n:], b)
		return n < len(dst)
	})
	return n
}

// Parse only the dedicated IPv4 TCP test tuple. Never derive ISNs from payload:
// a wrong source offset must not be allowed to redefine the expected offset.
func boundaryHeaders(ip, tcp []byte) (port uint16, out bool, ok bool) {
	if len(ip) < 20 || ip[0]>>4 != 4 || ip[9] != 6 || len(tcp) < 20 {
		return
	}
	src, dst := binary.BigEndian.Uint32(ip[12:16]), binary.BigEndian.Uint32(ip[16:20])
	sport, dport := binary.BigEndian.Uint16(tcp), binary.BigEndian.Uint16(tcp[2:])
	if src == 0xc613f001 && dst == 0xc613f002 && dport == 9002 {
		return sport, false, true
	}
	if src == 0xc613f002 && dst == 0xc613f001 && sport == 9002 {
		return dport, true, true
	}
	return
}
func (d *boundaryCapture) raw(stage string, p []byte, slot int64, batch uint64, index int) {
	if stage == "batch_overflow" {
		d.issue("publish batch exceeds 64 packets")
		return
	}
	if len(p) < 20 || p[0]>>4 != 4 || p[9] != 6 {
		return
	}
	ihl := int(p[0]&15) * 4
	if ihl < 20 || ihl+20 > len(p) {
		d.issue("malformed IPv4 TCP header at " + stage)
		return
	}
	tcp := p[ihl:]
	port, out, ok := boundaryHeaders(p, tcp)
	if !ok {
		return
	}
	thl := int(tcp[12]>>4) * 4
	if thl < 20 || ihl+thl > len(p) || int(binary.BigEndian.Uint16(p[2:4])) != len(p) || binary.BigEndian.Uint16(p[6:8])&0x3fff != 0 {
		d.issue("malformed/fragmented test packet at " + stage)
		return
	}
	body := p[ihl+thl:]
	d.packet(port, out, tcp, boundaryPayload{raw: body, length: len(body)}, boundaryRecord{Stage: stage, Slot: slot, Batch: batch, Index: index})
}
func (d *boundaryCapture) stack(p *gv.PacketBuffer) {
	ip, tcp := p.NetworkHeader().Slice(), p.TransportHeader().Slice()
	port, out, ok := boundaryHeaders(ip, tcp)
	if !ok {
		return
	}
	if !out {
		d.issue("unexpected inbound packet at stack write")
		return
	}
	views, skip := p.AsViewList()
	d.packet(port, out, tcp, boundaryPayload{views: views, skip: skip + len(ip) + len(tcp), length: p.Data().Size()}, boundaryRecord{Stage: "stack_write", Slot: -1, Index: -1})
}
func (d *boundaryCapture) packet(port uint16, out bool, tcp []byte, p boundaryPayload, r boundaryRecord) {
	if (r.Stage == "ring_ingress" && out) || (r.Stage != "ring_ingress" && !out) {
		d.issue("wrong direction at " + r.Stage)
		return
	}
	r.Seq = binary.BigEndian.Uint32(tcp[4:])
	r.Flags = tcp[13]
	r.Length = p.length
	f := d.flow(port, r.Flags&2 != 0)
	if f == nil {
		return
	}
	isn := &f.client
	if out {
		isn = &f.server
	}
	if r.Flags&2 != 0 {
		isn.CompareAndSwap(nil, &boundaryISN{r.Seq})
		if isn.Load().seq != r.Seq {
			d.issue("ISN changed/tuple reused")
			return
		}
		if out {
			client := f.client.Load()
			if client == nil || binary.BigEndian.Uint32(tcp[8:]) != client.seq+1 {
				d.issue("SYN-ACK does not match observed SYN")
				return
			}
		}
	}
	i := 0
	switch r.Stage {
	case "stack_write":
		i = 1
	case "ring_publish":
		i = 2
	}
	s := &f.state[i]
	s.mu.Lock()
	known := isn.Load()
	if known != nil {
		r.Offset = int64(uint32(r.Seq - known.seq - 1))
		if r.Flags&2 != 0 {
			r.Offset = 0
		}
	}
	r.Retransmit = p.length > 0 && r.Offset < s.high
	if p.length > 0 {
		s.high = max(s.high, r.Offset+int64(p.length))
	}
	s.history[s.seen%boundaryHistoryLimit] = r
	s.seen++
	id := f.identity.Load()
	if p.length == 0 {
		s.mu.Unlock()
		return
	}
	if known == nil || id == nil || r.Offset < 0 || r.Offset+int64(p.length) > wordPayloadSize {
		s.mu.Unlock()
		d.issue("unmapped/out-of-range payload at " + r.Stage)
		return
	}
	bad, checked := -1, 0
	p.walk(func(b []byte) bool {
		at := boundaryWordDifference(b, id.Transfer, id.Stream, r.Offset+int64(checked))
		if at >= 0 {
			bad = checked + at
			return false
		}
		checked += len(b)
		return true
	})
	var difference *boundaryDifference
	if bad >= 0 {
		difference = captureBoundaryDifference(p, r.Offset, bad, *id)
	} else if checked != p.length {
		s.mu.Unlock()
		d.issue("packet view length mismatch")
		return
	}
	s.bytes += uint64(p.length)
	covered := s.cover(r.Offset, r.Offset+int64(p.length))
	s.mu.Unlock()
	if !covered {
		d.issue("coverage interval budget exhausted")
	}
	if difference != nil {
		d.failure(f, r, difference, "payload_mismatch")
	}
}

// The normal path checks aligned words; only the two packet/view edges need
// partial-word handling. No reference payload, packet clone, or per-byte loop.
func boundaryWordDifference(p []byte, transfer uint64, stream int, offset int64) int {
	original := p
	done := 0
	if offset&7 != 0 && len(p) > 0 {
		var word [8]byte
		binary.LittleEndian.PutUint64(word[:], payloadWord(transfer, stream, offset))
		n := min(len(p), 8-int(offset&7))
		if !bytes.Equal(p[:n], word[offset&7:int(offset&7)+n]) {
			for i := 0; i < n; i++ {
				if p[i] != word[int(offset&7)+i] {
					return i
				}
			}
		}
		p = p[n:]
		offset += int64(n)
		done += n
	}
	base := (transfer<<32 | uint64(stream)<<24 | uint64(offset/8)) * 0xbf58476d1ce4e5b9
	for len(p) >= 8 {
		want := bits.RotateLeft64(base, 23)
		if binary.LittleEndian.Uint64(p) != want {
			var word [8]byte
			binary.LittleEndian.PutUint64(word[:], want)
			for i := range word {
				if p[i] != word[i] {
					return done + i
				}
			}
		}
		base += 0xbf58476d1ce4e5b9
		p = p[8:]
		done += 8
	}
	if len(p) > 0 {
		var word [8]byte
		binary.LittleEndian.PutUint64(word[:], bits.RotateLeft64(base, 23))
		if !bytes.Equal(p, word[:len(p)]) {
			for i := range p {
				if original[done+i] != word[i] {
					return done + i
				}
			}
		}
	}
	return -1
}

type boundaryDifference struct {
	Offset           int64 `json:"offset"`
	ContextOffset    int64 `json:"context_offset"`
	Expected, Actual string
	ExpectedWord     decodedPayloadWord  `json:"expected_word"`
	ActualWord       *decodedPayloadWord `json:"actual_word,omitempty"`
	Source           *decodedPayloadWord `json:"confirmed_source,omitempty"`
	SourceAt         int64               `json:"source_observed_at,omitempty"`
	Shift            *int64              `json:"source_offset_minus_received_offset,omitempty"`
}

func captureBoundaryDifference(p boundaryPayload, offset int64, bad int, id boundaryIdentity) *boundaryDifference {
	start := max(0, bad-int((offset+int64(bad))&7))
	var actual, expected [64]byte
	n := p.copyAt(actual[:], start)
	at := offset + int64(start)
	fillPayloadWords(expected[:n], id.Transfer, id.Stream, at)
	d := &boundaryDifference{Offset: offset + int64(bad), ContextOffset: at, Expected: hexBytes(expected[:n]), Actual: hexBytes(actual[:n]), ExpectedWord: decodePayloadWord(payloadWord(id.Transfer, id.Stream, offset+int64(bad)))}
	if at&7 == 0 && n >= 8 {
		word := decodePayloadWord(binary.LittleEndian.Uint64(actual[:]))
		d.ActualWord = &word
	}
	v := wordVerifier{transfer: id.Transfer, stream: id.Stream, first: &wordDifference{}, evidenceAt: at}
	v.evidenceN = copy(v.evidence[:], actual[:n])
	v.decodeSource()
	d.Source, d.SourceAt, d.Shift = v.first.Source, v.first.SourceAt, v.first.Shift
	return d
}
func (d *boundaryCapture) failure(f *boundaryFlow, r boundaryRecord, difference any, reason string) bool {
	d.failed.Store(true)
	n := d.number()
	if n > boundaryFailureLimit {
		return false
	}
	history := make(map[string][]boundaryRecord)
	for i, name := range boundaryStages {
		history[name] = f.state[i].recent()
	}
	d.report(map[string]any{"test": "word_boundary_failure", "verdict": "integrity_failure", "number": n, "limit": boundaryFailureLimit, "mode": d.mode, "client_port": f.port, "identity": f.identity.Load(), "record": r, "difference": difference, "reason": reason, "history": history})
	return true
}
func (d *boundaryCapture) hostFailure(local string, difference *wordDifference, reason string) bool {
	port, err := boundaryPort(local)
	if err != nil {
		d.issue(err.Error())
		return false
	}
	f := d.flow(port, false)
	if f == nil {
		return false
	}
	if !f.hostReported.CompareAndSwap(false, true) {
		if f.hostEmitted.Load() && reason != "payload_mismatch_detected" {
			d.report(map[string]any{"test": "word_boundary_host_end", "mode": d.mode, "client_port": f.port, "identity": f.identity.Load(), "difference": difference, "reason": reason})
		}
		return false
	}
	emitted := d.failure(f, boundaryRecord{Stage: "host_receive", Slot: -1, Index: -1}, difference, reason)
	f.hostEmitted.Store(emitted)
	return emitted
}

type boundaryEchoReader struct {
	reader net.Conn
	d      *boundaryCapture
	flow   *boundaryFlow
	offset int64
}

func (r *boundaryEchoReader) Read(p []byte) (int, error) {
	n, err := r.reader.Read(p)
	if n == 0 {
		return n, err
	}
	if r.flow == nil {
		port, e := boundaryPort(r.reader.RemoteAddr().String())
		if e == nil {
			r.flow = r.d.flow(port, false)
		}
	}
	f := r.flow
	if f == nil {
		r.d.issue("echo flow missing")
		return n, err
	}
	id := f.identity.Load()
	if id == nil {
		r.d.issue("echo identity missing")
		return n, err
	}
	s := &f.state[3]
	record := boundaryRecord{Stage: "echo_read", Offset: r.offset, Length: n, Slot: -1, Index: -1}
	bad := boundaryWordDifference(p[:n], id.Transfer, id.Stream, r.offset)
	s.mu.Lock()
	s.history[s.seen%boundaryHistoryLimit] = record
	s.seen++
	s.bytes += uint64(n)
	covered := s.cover(r.offset, r.offset+int64(n))
	s.mu.Unlock()
	if !covered {
		r.d.issue("echo coverage interval budget exhausted")
	}
	if bad >= 0 {
		r.d.failure(f, record, captureBoundaryDifference(boundaryPayload{raw: p[:n], length: n}, r.offset, bad, *id), "payload_mismatch")
	}
	r.offset += int64(n)
	return n, err
}
func (d *boundaryCapture) echo(c net.Conn) (int64, error) {
	return io.Copy(c, &boundaryEchoReader{reader: c, d: d})
}
func (d *boundaryCapture) complete(transfer uint64, streams int) error {
	if err := wordBoundaryRingFault(d.fixture); err != nil {
		d.failed.Store(true)
		d.ringOnce.Do(func() {
			if d.number() <= boundaryFailureLimit {
				d.report(map[string]any{"test": "word_boundary_ring_rejection", "verdict": "integrity_failure", "mode": d.mode, "reason": err.Error()})
			}
		})
	}
	d.listMu.Lock()
	flows := append([]*boundaryFlow(nil), d.list...)
	d.listMu.Unlock()
	count := 0
	for _, f := range flows {
		id := f.identity.Load()
		if id == nil || id.Transfer != transfer {
			continue
		}
		count++
		for i, name := range boundaryStages {
			s := &f.state[i]
			s.mu.Lock()
			ok := s.spanCount == 1 && s.spans[0] == (boundarySpan{0, wordPayloadSize})
			s.mu.Unlock()
			if !ok {
				d.issue(fmt.Sprintf("incomplete %s coverage for port %d", name, f.port))
			}
		}
	}
	if count != streams {
		d.issue("missing bound flow at transfer completion")
	}
	var err error
	if d.failed.Load() {
		err = errPayloadIntegrity
	}
	if d.incomplete.Load() {
		err = errors.Join(err, errDiagnosticIncomplete)
	}
	d.report(map[string]any{"test": "word_boundary_coverage", "transfer": transfer, "flows": count, "expected_flows": streams, "verdict": integrityVerdict(err), "stages": boundaryStages, "failure_records_seen": boundaryFailureNumber.Load()})
	return err
}
