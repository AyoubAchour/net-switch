//go:build windows

package wintun

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"math"
	"strconv"
	"strings"
	"sync"
	"testing"

	"gvisor.dev/gvisor/pkg/tcpip/checksum"
)

// Synthetic packets only: no sockets, adapters, native rings or engine.
func integrityTestPacket(out bool, port uint16, seq, ack uint32, flags byte, body []byte) []byte {
	p := make([]byte, 40+len(body))
	p[0], p[8], p[9] = 0x45, 64, 6
	binary.BigEndian.PutUint16(p[2:], uint16(len(p)))
	copy(p[12:20], []byte{198, 19, 240, 1, 198, 19, 240, 2})
	binary.BigEndian.PutUint16(p[20:], port)
	binary.BigEndian.PutUint16(p[22:], 9002)
	if out {
		p[15], p[19] = p[19], p[15]
		copy(p[20:24], []byte{0x23, 0x2a, byte(port >> 8), byte(port)})
	}
	binary.BigEndian.PutUint32(p[24:], seq)
	binary.BigEndian.PutUint32(p[28:], ack)
	p[32], p[33] = 0x50, flags
	copy(p[40:], body)
	binary.BigEndian.PutUint16(p[10:], ^checksum.Checksum(p[:20], 0))
	pseudo := append(bytes.Clone(p[12:20]), 0, 6, byte((len(p)-20)>>8), byte(len(p)-20))
	binary.BigEndian.PutUint16(p[36:], ^checksum.Checksum(p[20:], checksum.Checksum(pseudo, 0)))
	return p
}

func integrityTestHandshake(d *integrityDiagnostic, port uint16, clientISN, serverISN uint32, id uint64) *integrityConnection {
	d.packet("dll_receive", integrityTestPacket(false, port, clientISN, 0, 2, nil))
	d.packet("stack_output", integrityTestPacket(true, port, serverISN, clientISN+1, 18, nil))
	return d.bind(netTestLocal(port), id, "synthetic")
}

func netTestLocal(port uint16) string {
	// Keep the tuple formatting independent of the packet parser.
	return "198.19.240.1:" + strconv.FormatUint(uint64(port), 10)
}

func integrityTestBody(id uint64, offset, size int) []byte {
	b := make([]byte, size)
	for i := range b {
		b[i] = integrityByte(id, int64(offset+i))
	}
	return b
}

func TestIntegrityPattern(t *testing.T) {
	// At offset 0 the identity's low byte is visible; at offset 24 the
	// position block is 1, XORed with the unmodified original byte (312).
	if integrityByte(0x102, 0) != 2 || integrityByte(0x102, 1) != 12 || integrityByte(0x102, 24) != 57 {
		t.Fatal("payload identity/position encoding changed")
	}
	if bytes.Equal(integrityTestBody(257, 0, 65536), integrityTestBody(513, 0, 65536)) ||
		bytes.Equal(integrityTestBody(257, 0, 65536), integrityTestBody(258, 0, 65536)) ||
		bytes.Equal(integrityTestBody(257, 0, 1024), integrityTestBody(257, 64256, 1024)) {
		t.Fatal("warmup, stream or old-pattern-period substitution is invisible")
	}
}

func TestIntegritySequenceBoundaries(t *testing.T) {
	d := newIntegrityDiagnostic()
	clientISN := uint32(0xfffffff0)
	serverISN := uint32(0xffffffe0)
	c := integrityTestHandshake(d, 51000, clientISN, serverISN, 257)
	if c == nil {
		t.Fatal("missing identity")
	}
	// Out of order, then retransmission, then wrap: no arrival-order offsets.
	for _, offset := range []int{64, 0, 64, 128} {
		for _, out := range []bool{false, true} {
			isn := clientISN
			if out {
				isn = serverISN
			}
			p := integrityTestPacket(out, 51000, isn+1+uint32(offset), 0, 24, integrityTestBody(257, offset, 64))
			d.packet("boundary", p)
		}
	}
	if err := d.err(); err != nil {
		t.Fatal(err)
	}
	if got := c.history(); len(got) != 10 || got[9].Offset != 128 || got[9].ChecksumChecked {
		t.Fatalf("bad sequence/checksum metadata: %+v", got)
	}
	if integrityOffset(100, 100, true) != 0 || integrityOffset(100, 100, false) != -1 {
		t.Fatal("SYN consumption or keepalive sequence mishandled")
	}
	// FIN and pure ACK are not payload bytes, even at the transfer end.
	d.packet("boundary", integrityTestPacket(false, 51000, clientISN+1+integrityTransferSize, 0, 17, nil))
	if err := d.err(); err != nil {
		t.Fatal(err)
	}
}

func TestIntegrityFirstFailureAndBoundedHistory(t *testing.T) {
	d := newIntegrityDiagnostic()
	emitted := make(map[string]int)
	d.emit = func(_ *integrityConnection, stage string, f integrityFailure) {
		emitted[stage]++
		if len(f.Recent) > 64 {
			t.Fatal("unbounded immediate evidence")
		}
	}
	c := integrityTestHandshake(d, 51000, 100, 200, 257)
	for i := range 100 {
		p := integrityTestPacket(false, 51000, 101+uint32(i*64), 0, 24, integrityTestBody(257, i*64, 64))
		d.packet("dll_receive", p)
	}
	good := integrityTestPacket(false, 51000, 101+7000, 0, 24, integrityTestBody(257, 7000, 64))
	bad := bytes.Clone(good)
	bad[40+13] ^= 0x40
	d.native("dll_receive", good, bad)
	f := c.Failures["dll_receive_copy"]
	if f.Offset != 7013 || len(f.Recent) != 64 || f.Packet.TCPChecksum || !f.Packet.IPChecksum || len(c.Failures) != 2 {
		t.Fatalf("wrong localization: %+v, failures=%v", f, c.Failures)
	}
	if _, bad := c.Failures["dll_receive"]; bad {
		t.Fatal("blamed intact native bytes")
	}
	if c.Failures["dll_receive_copy_equal"].Offset != 53 {
		t.Fatal("missing whole-packet copy comparison")
	}
	d.packet("dll_receive_copy", integrityTestPacket(false, 51000, 101+8000, 0, 24, integrityTestBody(258, 8000, 64)))
	if c.Failures["dll_receive_copy"].Offset != 7013 {
		t.Fatal("overwrote first failure")
	}
	if len(c.history()) != 64 || d.err() == nil {
		t.Fatal("unbounded history or failed to invalidate")
	}
	if len(emitted) != 2 || emitted["dll_receive_copy"] != 1 || emitted["dll_receive_copy_equal"] != 1 {
		t.Fatalf("first failure not emitted exactly once before teardown: %v", emitted)
	}
}

func TestIntegrityStreamSubstitutionAndHostOffset(t *testing.T) {
	d := newIntegrityDiagnostic()
	c := integrityTestHandshake(d, 51000, 100, 200, 257)
	d.stream("echo_read", c.Tuple, 0, integrityTestBody(257, 0, 100))
	d.stream("echo_read", c.Tuple, 100, integrityTestBody(258, 100, 100))
	// Difference occurs at offset 112 (next low identity byte), not at the
	// read chunk's beginning. Chunking must not alter the reported offset.
	if got := c.Failures["echo_read"].Offset; got != 112 {
		t.Fatalf("offset=%d", got)
	}
	r := &integrityReader{reader: bytes.NewReader(append(integrityTestBody(257, 0, 73), 99)), d: d, stage: "host_receive", local: c.Tuple}
	buf := make([]byte, 7)
	for {
		_, err := r.Read(buf)
		if err != nil {
			break
		}
	}
	if got := c.Failures["host_receive"].Offset; got != 73 {
		t.Fatalf("host offset=%d", got)
	}
	d.hashes(c, []byte{1, 2}, []byte{3, 4})
	if c.HostExpectedHash != "0102" || c.HostActualHash != "0304" {
		t.Fatal("hash evidence lost")
	}
}

func TestIntegrityMissingAndReusedIdentity(t *testing.T) {
	d := newIntegrityDiagnostic()
	d.packet("stack_ingress", integrityTestPacket(false, 51000, 101, 0, 24, []byte{1}))
	if d.err() != nil || d.unregisteredPayload["stack_ingress"] != 1 {
		t.Fatal("foreign payload treated as a missing active connection")
	}
	d = newIntegrityDiagnostic()
	first := integrityTestHandshake(d, 51000, 100, 200, 257)
	second := integrityTestHandshake(d, 51000, 1000000000, 2000000000, 513)
	// Late old packet still belongs to the first transfer, not the new tuple.
	d.packet("dll_receive", integrityTestPacket(false, 51000, 101, 0, 24, integrityTestBody(257, 0, 64)))
	if first == second || first.Coverage["dll_receive"].Bytes != 64 || second.Coverage["dll_receive"].Bytes != 0 || d.err() != nil {
		t.Fatal("late packet assigned to reused tuple")
	}
	d.complete(second)
	if d.err() == nil {
		t.Fatal("missing boundary coverage reported clean")
	}
	d = newIntegrityDiagnostic()
	for i := 0; i <= integrityConnectionLimit; i++ {
		d.packet("dll_receive", integrityTestPacket(false, uint16(51000+i), 100, 0, 2, nil))
		d.bind(netTestLocal(uint16(51000+i)), uint64(i+1), "bounded")
	}
	if len(d.connections) != integrityConnectionLimit || d.err() == nil {
		t.Fatal("connection bound not enforced")
	}
}

func TestIntegrityLatePreviousFixtureAndMidflight(t *testing.T) {
	d := newIntegrityDiagnostic()
	// Round-2 evidence: 62320 belonged to the preceding DLL fixture, not
	// this fixture's host sockets. Its late payload is not lost active evidence.
	c := integrityTestHandshake(d, 62321, 100, 200, 257)
	d.packet("ours_receive", integrityTestPacket(false, 62320, 3563722830, 70873961, 24, integrityTestBody(2312, 0, 128)))
	d.packet("late_syn_data", integrityTestPacket(false, 62320, 3563722829, 0, 2, integrityTestBody(2312, 0, 128)))
	d.packet("ours_receive", integrityTestPacket(false, 62321, 101, 201, 24, integrityTestBody(257, 0, 128)))
	if d.err() != nil || c.Coverage["ours_receive"].Bytes != 128 || d.unregisteredPayload["ours_receive"] != 1 {
		t.Fatal("late fixture data poisoned the current transfer")
	}
	// Independent host registration still works when the observer missed both
	// SYNs; the first observed packet need not start at stream offset zero.
	d = newIntegrityDiagnostic()
	reference := integrityTestBody(513, 0, 16384)
	c = d.bind(netTestLocal(51000), 513, "midflight", reference)
	d.packet("stack_ingress", integrityTestPacket(false, 51000, 101+4096, 201, 24, bytes.Clone(reference[4096:4224])))
	d.packet("stack_output", integrityTestPacket(true, 51000, 201+8192, 101, 24, bytes.Clone(reference[8192:8320])))
	if !c.ClientKnown || !c.ServerKnown || c.ClientISN != 100 || c.ServerISN != 200 || d.err() != nil {
		t.Fatalf("midflight: %+v %v", c, d.err())
	}
	// Late/retransmitted SYNs must not reset inferred offsets or lose the bind.
	for range 2 {
		d.packet("stack_ingress", integrityTestPacket(false, 51000, 100, 0, 2, nil))
	}
	if len(d.connections) != 1 || d.connections[0].ID != 513 {
		t.Fatal("late SYN replaced bound identity")
	}
	d.complete(c)
	if !errors.Is(d.err(), errDiagnosticIncomplete) || errors.Is(d.err(), errPayloadIntegrity) {
		t.Fatalf("partial coverage mislabeled: %v", d.err())
	}
}

func TestIntegritySYNACKWithoutSYNAndLateSYNPressure(t *testing.T) {
	d := newIntegrityDiagnostic()
	d.packet("stack_output", integrityTestPacket(true, 51000, 200, 101, 18, nil))
	c := d.bind(netTestLocal(51000), 257, "synack")
	if c.ClientISN != 100 || c.ServerISN != 200 || !c.ClientKnown || !c.ServerKnown {
		t.Fatal("SYNACK did not recover handshake")
	}
	for i := range 100 {
		d.packet("dll_receive", integrityTestPacket(false, uint16(52000+i), uint32(i), 0, 2, nil))
	}
	if d.err() != nil || len(d.connections) != integrityConnectionLimit {
		t.Fatal("late unbound SYNs exhausted active evidence")
	}
	d.packet("dll_receive", integrityTestPacket(false, 51000, 101, 201, 24, integrityTestBody(257, 0, 128)))
	if c.Coverage["dll_receive"].Bytes != 128 {
		t.Fatal("lost bound identity under SYN pressure")
	}
}

func TestIntegrityBindBeforeLateHandshake(t *testing.T) {
	for _, syn := range []bool{false, true} {
		d := newIntegrityDiagnostic()
		c := d.bind(netTestLocal(51000), 257, "bound before capture", integrityTestBody(257, 0, 16384))
		if syn {
			d.packet("dll_receive", integrityTestPacket(false, 51000, 100, 0, 2, nil))
		}
		d.packet("stack_output", integrityTestPacket(true, 51000, 200, 101, 18, nil))
		d.packet("dll_receive", integrityTestPacket(false, 51000, 101, 201, 24, integrityTestBody(257, 0, 128)))
		if len(d.connections) != 1 || c.Coverage["dll_receive"].Bytes != 128 || d.err() != nil {
			t.Fatalf("late handshake forked identity: %v", d.err())
		}
	}
}

func TestIntegrityFastHostFirstDifference(t *testing.T) {
	d := newIntegrityDiagnostic()
	d.boundary = "receive"
	c := integrityTestHandshake(d, 51000, 100, 200, 257)
	c.reference = integrityTestBody(257, 0, 8192)
	body := bytes.Clone(c.reference)
	body[4111] ^= 32
	r := &integrityReader{reader: bytes.NewReader(body), d: d, stage: "host_receive", connection: c, fastReference: c.reference}
	buf := make([]byte, 1023)
	for {
		_, err := r.Read(buf)
		if err != nil {
			break
		}
	}
	if f := c.Failures["host_receive"]; f.Offset != 4111 || r.offset != 8192 || integrityVerdict(d.err()) != "integrity_failure" {
		t.Fatalf("fast host check lost offset: %+v", f)
	}
}

func TestIntegrityFastOracleAndSeparateVerdicts(t *testing.T) {
	d := newIntegrityDiagnostic()
	d.boundary = "receive"
	c := integrityTestHandshake(d, 51000, 100, 200, 257)
	c.reference = integrityTestBody(257, 0, 65536)
	for _, offset := range []int{0, 1, 15, 16, 4095, 8193} {
		p := integrityTestPacket(false, 51000, 101+uint32(offset), 201, 24, bytes.Clone(c.reference[offset:offset+9000]))
		d.native("dll_receive", p, bytes.Clone(p))
	}
	if d.err() != nil {
		t.Fatal(d.err())
	}
	d.complete(c)
	if integrityVerdict(d.err()) != "diagnostic_incomplete" || len(c.Failures) != 0 {
		t.Fatalf("%v", d.err())
	}
	c.reference = integrityTestBody(257, 0, 65536)
	bad := bytes.Clone(c.reference[8193 : 8193+9000])
	bad[7] ^= 64
	d.packet("dll_receive", integrityTestPacket(false, 51000, 101+8193, 201, 24, bad))
	if c.Failures["dll_receive"].Offset != 8200 || integrityVerdict(d.err()) != "integrity_failure" {
		t.Fatalf("mismatch lost behind incomplete: %v", d.err())
	}
}

func TestIntegrityMalformedAndHeaderCopy(t *testing.T) {
	d := newIntegrityDiagnostic()
	c := integrityTestHandshake(d, 51000, 100, 200, 257)
	p := integrityTestPacket(false, 51000, 101, 0, 24, integrityTestBody(257, 0, 64))
	copyWithBadTTL := bytes.Clone(p)
	copyWithBadTTL[8]--
	d.native("dll_receive", p, copyWithBadTTL)
	if c.Failures["dll_receive_copy_equal"].Offset != 8 {
		t.Fatal("header copy mismatch invisible")
	}
	p[32] = 0xf0
	if _, err := parseIntegrityPacket(p[:40]); err == nil {
		t.Fatal("malformed length accepted")
	}
	p = integrityTestPacket(false, 51000, 101, 0, 24, nil)
	p[6] = 0x20
	d.packet("fragment", p)
	if d.issues["fragment"] == "" {
		t.Fatal("fragment silently marked checked")
	}
}

func TestIntegrityPipelineLocalization(t *testing.T) {
	for _, mode := range []string{"dll", "ours"} {
		stages := []string{mode + "_receive", "stack_ingress", "echo_read", "stack_output", mode + "_send", "host_receive"}
		for broken := range stages {
			t.Run(mode+"/"+stages[broken], func(t *testing.T) {
				d := newIntegrityDiagnostic()
				c := integrityTestHandshake(d, 51000, 100, 200, 257)
				body := integrityTestBody(257, 0, 128)
				for i, stage := range stages {
					if i == broken {
						body[37] ^= 0x40
					}
					p := integrityTestPacket(i >= 3, 51000, 101, 0, 24, body)
					if i >= 3 {
						p = integrityTestPacket(true, 51000, 201, 0, 24, body)
					}
					switch i {
					case 0, 4:
						d.native(stage, p, bytes.Clone(p))
					case 2, 5:
						d.stream(stage, c.Tuple, 0, body)
					default:
						d.packet(stage, p)
					}
				}
				for i, stage := range stages {
					f, failed := c.Failures[stage]
					if failed != (i >= broken) || (failed && f.Offset != 37) {
						t.Fatalf("first bad boundary %s; %s failure=%+v present=%v", stages[broken], stage, f, failed)
					}
				}
			})
		}
	}
}

func TestIntegrityConcurrentStreamsAndControl(t *testing.T) {
	d := newIntegrityDiagnostic()
	var wg sync.WaitGroup
	for i := range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			port := uint16(51000 + i)
			id := uint64(257 + i)
			c := integrityTestHandshake(d, port, 100, 200, id)
			for offset := 0; offset < 10000; offset += 100 {
				d.packet("stack_ingress", integrityTestPacket(false, port, uint32(101+offset), 0, 24, integrityTestBody(id, offset, 100)))
				d.stream("echo_read", c.Tuple, int64(offset), integrityTestBody(id, offset, 100))
			}
		}()
	}
	wg.Wait()
	// Windows can close the previous fixture's connection after its TCP stack
	// has gone away. Empty unmatched RST/ACK packets aren't corrupt payloads.
	d.packet("dll_receive", integrityTestPacket(false, 52000, 300, 0, 20, nil))
	if err := d.err(); err != nil || d.ignoredControl["dll_receive"] != 1 {
		t.Fatalf("%v, %+v", err, d.ignoredControl)
	}
	// Bound application readers retain their actual connection on tuple reuse.
	old := integrityTestHandshake(d, 53000, 100, 200, 513)
	r := &integrityReader{reader: bytes.NewReader(integrityTestBody(513, 0, 128)), d: d, stage: "host_receive", local: old.Tuple, connection: old}
	newer := integrityTestHandshake(d, 53000, 1000000000, 2000000000, 769)
	if _, err := r.Read(make([]byte, 128)); err != nil {
		t.Fatal(err)
	}
	if old.Coverage["host_receive"].Bytes != 128 || newer.Coverage["host_receive"].Bytes != 0 || d.err() != nil {
		t.Fatal("reused tuple stole old application's stream identity")
	}
}

func TestIntegrityHooks(t *testing.T) {
	if !integrityHooksEnabled {
		t.Skip("tagged diagnostic binary only")
	}
	d := newIntegrityDiagnostic()
	detach := attachIntegrityRings(t, d)
	defer detach()
	c := integrityTestHandshake(d, 51000, 100, 200, 257)
	for _, out := range []bool{false, true} {
		seq, stage := uint32(101), "ours_receive"
		if out {
			seq, stage = 201, "ours_send"
		}
		p := integrityTestPacket(out, 51000, seq, 0, 24, integrityTestBody(257, 0, 128))
		copied := bytes.Clone(p)
		copied[40+23] ^= 0x40
		if out {
			observeRingSend(p, copied)
		} else {
			observeRingReceive(p, copied)
		}
		before := c.Failures[stage+"_copy"].Actual
		clear(p)
		clear(copied)
		if before == "" || c.Failures[stage+"_copy"].Actual != before {
			t.Fatal("observer retained borrowed packet memory")
		}
	}
	// A later copy in the same batch could overwrite an earlier reservation.
	// Observe the actual final bytes at publication, not just each initial copy.
	late := integrityTestHandshake(d, 51001, 100, 200, 258)
	source := integrityTestPacket(true, 51001, 201, 0, 24, integrityTestBody(258, 0, 128))
	native := bytes.Clone(source)
	var batch integrityRingBatch
	batch.add(native, source)
	native[40+47] ^= 0x40
	batch.publish()
	if late.Failures["ours_send"].Offset != 47 {
		t.Fatal("batch overwrote a reservation after it had already been checked")
	}
}

func TestPerformanceInvalidSamples(t *testing.T) {
	ours, dll := newPerformanceSamples(3, "ours", "tcp_8_MBps"), newPerformanceSamples(3, "dll", "tcp_8_MBps")
	for i := range ours {
		ours[i].finish(90, nil)
		dll[i].finish(100, nil)
	}
	if r, err := pairedSampleRatios(ours, dll); err != nil || median(r) != 0.9 {
		t.Fatalf("%v %v", r, err)
	}
	original := errors.New("TCP payload hash mismatch")
	dll[1].finish(0, original)
	r, err := pairedSampleRatios(ours, dll)
	if r != nil || !errors.Is(err, original) || !strings.Contains(err.Error(), "integrity-invalid comparison") || !strings.Contains(err.Error(), "pair=1 mode=dll metric=tcp_8_MBps") {
		t.Fatalf("failure lost: %v %v", r, err)
	}
	b, err := json.Marshal(dll)
	if err != nil || !bytes.Contains(b, []byte(`"value":null`)) || dll[2].Pair != 2 || dll[2].Value == nil {
		t.Fatalf("failed sample became zero or pair dropped: %s %v", b, err)
	}
	for _, value := range []float64{0, -1, math.NaN(), math.Inf(1)} {
		dll[1].finish(value, nil)
		if dll[1].Value != nil || dll[1].Status != "invalid" {
			t.Fatal("unusable sample valid")
		}
	}
	dll[1].finish(100, nil)
	dll[1], dll[2] = dll[2], dll[1]
	if r, err := pairedSampleRatios(ours, dll); r != nil || err == nil {
		t.Fatal("pair substitution accepted")
	}
	if r, err := pairedSampleRatios(ours, dll[:2]); r != nil || err == nil {
		t.Fatal("missing pair accepted")
	}
	if r, err := pairedSampleRatios(ours, newPerformanceSamples(3, "dll", "tcp_8_MBps")); r != nil || err == nil {
		t.Fatal("unexecuted sample accepted")
	}
	inprocess := newPerformanceSamples(3, "inprocess", "tcp_8_MBps")
	for i := range inprocess {
		inprocess[i].finish(100, nil)
	}
	if r, err := pairedSampleRatios(ours, inprocess, "inprocess"); err != nil || median(r) != 0.9 {
		t.Fatalf("inprocess reference: %v %v", r, err)
	}
}

func BenchmarkIntegrityPayloadCheck(b *testing.B) {
	body := integrityTestBody(257, 0, 1<<20)
	c := &integrityConnection{ID: 257, Failures: make(map[string]integrityFailure), Coverage: make(map[string]integrityCoverage)}
	c.reference = bytes.Clone(body) // Different allocation: no pointer-equality shortcut.
	b.SetBytes(int64(len(body)))
	b.ResetTimer()
	for range b.N {
		c.check("boundary", body, 0, integrityRecord{})
	}
	if len(c.Failures) != 0 {
		b.Fatal(c.Failures)
	}
}

func BenchmarkIntegrityNativePacket(b *testing.B) {
	d := newIntegrityDiagnostic()
	d.boundary = "receive"
	c := integrityTestHandshake(d, 51000, 100, 200, 257)
	c.reference = integrityTestBody(257, 0, 8192)
	native := integrityTestPacket(false, 51000, 101, 201, 24, c.reference)
	copied := bytes.Clone(native)
	b.SetBytes(8192)
	b.ResetTimer()
	for range b.N {
		d.native("dll_receive", native, copied)
	}
	if d.err() != nil {
		b.Fatal(d.err())
	}
}

func TestIntegrityPacketHotPathAllocations(t *testing.T) {
	d := newIntegrityDiagnostic()
	var packets [8][]byte
	var copies [8][]byte
	var connections [8]*integrityConnection
	for i := range packets {
		id, port := uint64(257+i), uint16(51000+i)
		c := integrityTestHandshake(d, port, 100, 200, id)
		c.reference = integrityTestBody(id, 0, 8192)
		connections[i] = c
		packets[i] = integrityTestPacket(false, port, 101, 201, 24, c.reference)
		copies[i] = bytes.Clone(packets[i])
	}
	allocations := testing.AllocsPerRun(100, func() {
		for i, p := range packets {
			d.native("dll_receive", p, copies[i])
			d.packet("stack_ingress", copies[i])
		}
	})
	if allocations != 0 {
		t.Fatalf("clean packet checking allocates: %.1f per eight-stream batch", allocations)
	}
	if err := d.err(); err != nil {
		t.Fatal(err)
	}
	for _, c := range connections {
		for _, stage := range []string{"dll_receive", "dll_receive_copy", "stack_ingress"} {
			if c.Coverage[stage].Bytes != 101*8192 {
				t.Fatalf("lost stream coverage: %s %s %+v", c.Tuple, stage, c.Coverage[stage])
			}
		}
	}
	// Binary identity still distinguishes ports; it is not a last-stream cache.
	packets[3][40+47] ^= 1
	d.native("dll_receive", packets[3], copies[3])
	if connections[3].Failures["dll_receive"].Offset != 47 {
		t.Fatal("wrong connection or offset after interleaving")
	}
	for i, c := range connections {
		if i != 3 && len(c.Failures) != 0 {
			t.Fatal("cross-stream attribution")
		}
	}
}
