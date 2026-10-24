//go:build windows && wintun_boundaries

package wintun

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net"
	"sync/atomic"
	"testing"

	ns "github.com/AyoubAchour/net-switch/internal/engine/stack"
	"gvisor.dev/gvisor/pkg/buffer"
	gv "gvisor.dev/gvisor/pkg/tcpip/stack"
)

type boundaryTestConn struct{ payloadTestConn }

func (*boundaryTestConn) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(198, 19, 240, 1), Port: 51000}
}

func TestWordBoundaryEchoAndImmediateHostHistory(t *testing.T) {
	d, events := boundaryFixture(t)
	body := make([]byte, 64)
	fillPayloadWords(body, 96, 4, 0)
	c := &boundaryTestConn{payloadTestConn{Reader: bytes.NewReader(body)}}
	r := &boundaryEchoReader{reader: c, d: d}
	out := make([]byte, 64)
	n, err := r.Read(out)
	if err != nil || n != 64 || !bytes.Equal(out, body) || len(*events) != 1 || (*events)[0]["record"].(boundaryRecord).Stage != "echo_read" {
		t.Fatal(n, err, *events)
	}
	d, events = boundaryFixture(t)
	c = &boundaryTestConn{payloadTestConn{Reader: bytes.NewReader(body)}}
	v := &wordVerifier{transfer: 96, stream: 5}
	_, _, err = receivePayloadWords(c, v, 64, func(diff *wordDifference) { d.hostFailure(netTestLocal(51000), diff, "payload_mismatch_detected") })
	if !errors.Is(err, errPayloadIntegrity) || len(*events) != 1 {
		t.Fatal(err, *events)
	}
	history := (*events)[0]["history"].(map[string][]boundaryRecord)
	f := d.flows[51000].Load()
	f.state[1].history[0].Seq = 42
	if history["stack_write"][0].Seq == 42 {
		t.Fatal("snapshot borrowed mutable history")
	}
	d.hostFailure(netTestLocal(51000), v.first, "payload_mismatch")
	if len(*events) != 2 || d.budget.Load() != 1 || (*events)[1]["test"] != "word_boundary_host_end" {
		t.Fatal(*events)
	}
}

func TestWordBoundaryMissingByteCannotEarnCoverage(t *testing.T) {
	d, _ := boundaryFixture(t)
	f := d.flows[51000].Load()
	for i := range f.state {
		f.state[i].cover(0, wordPayloadSize)
	}
	f.state[2] = boundaryState{}
	f.state[2].cover(0, 1024)
	f.state[2].cover(1025, wordPayloadSize)
	if err := d.complete(96, 1); !errors.Is(err, errDiagnosticIncomplete) || d.failed.Load() {
		t.Fatal("one missing byte credited", err)
	}
}

func TestWordBoundaryRejectedRingCannotEarnCleanSample(t *testing.T) {
	d, events := boundaryFixture(t)
	f := d.flows[51000].Load()
	for i := range f.state {
		f.state[i].cover(0, wordPayloadSize)
	}
	s := &Session{}
	s.corruptions.Store(1)
	d.fixture = &fixture{io: s}
	if err := d.complete(96, 1); !errors.Is(err, errPayloadIntegrity) || d.incomplete.Load() {
		t.Fatal("ring rejection hidden", err)
	}
	if len(*events) != 2 || (*events)[0]["test"] != "word_boundary_ring_rejection" {
		t.Fatal(*events)
	}
}

func boundaryFixture(t *testing.T) (*boundaryCapture, *[]map[string]any) {
	t.Helper()
	events := new([]map[string]any)
	d := &boundaryCapture{t: t, mode: "synthetic", budget: new(atomic.Uint64), emit: func(r map[string]any) { *events = append(*events, r) }}
	d.raw("ring_ingress", integrityTestPacket(false, 51000, 0xfffffff0, 0, 2, nil), 0, 1, 0)
	d.raw("stack_write", integrityTestPacket(true, 51000, 0xffffffe0, 0xfffffff1, 18, nil), -1, 0, 0)
	d.raw("ring_publish", integrityTestPacket(true, 51000, 0xffffffe0, 0xfffffff1, 18, nil), 0, 2, 0)
	d.bind(netTestLocal(51000), 96, 5)
	return d, events
}
func TestWordBoundaryOffsetsAndViews(t *testing.T) {
	for _, offset := range []int64{0, 1, 7, 8, 31, 25452288, wordPayloadSize - 128} {
		body := make([]byte, 128)
		fillPayloadWords(body, 96, 5, offset)
		for split := 0; split <= len(body); split++ {
			b := buffer.MakeWithData(body[:split])
			tail := buffer.MakeWithData(body[split:])
			b.Merge(&tail)
			p := boundaryPayload{views: b.AsViewList(), length: len(body)}
			done := 0
			p.walk(func(part []byte) bool {
				if at := boundaryWordDifference(part, 96, 5, offset+int64(done)); at >= 0 {
					t.Fatalf("offset=%d split=%d bad=%d", offset, split, at)
				}
				done += len(part)
				return true
			})
			b.Release()
			if done != len(body) {
				t.Fatal("missing view")
			}
		}
	}
}
func TestWordBoundarySequenceAndRetransmit(t *testing.T) {
	d, events := boundaryFixture(t)
	body := make([]byte, 128)
	fillPayloadWords(body, 96, 5, 32)
	isn := uint32(0xffffffe0)
	p := integrityTestPacket(true, 51000, isn+1+32, 0, 24, body)
	d.raw("stack_write", p, -1, 0, 0)
	d.raw("stack_write", p, -1, 0, 0)
	f := d.flows[51000].Load()
	h := f.state[1].recent()
	if len(*events) != 0 || h[len(h)-1].Offset != 32 || !h[len(h)-1].Retransmit || h[len(h)-2].Retransmit {
		t.Fatal(h, *events)
	}
	fillPayloadWords(p[40:], 96, 4, 66)
	d.raw("stack_write", p, -1, 0, 0)
	if len(*events) != 1 || !d.failed.Load() {
		t.Fatal(*events)
	}
	diff := (*events)[0]["difference"].(*boundaryDifference)
	if diff.Source == nil || diff.Source.Stream != 4 || diff.Shift == nil || *diff.Shift != 34 {
		t.Fatalf("wrong origin: %+v", diff)
	}
}
func TestWordBoundaryCoverageAndBudget(t *testing.T) {
	var s boundaryState
	for _, p := range []boundarySpan{{16, 32}, {0, 8}, {8, 16}, {4, 24}, {32, 64}} {
		if !s.cover(p.Start, p.End) {
			t.Fatal("coverage overflow")
		}
	}
	if s.spanCount != 1 || s.spans[0] != (boundarySpan{0, 64}) {
		t.Fatal(s.spans, s.spanCount)
	}
	d, events := boundaryFixture(t)
	f := d.flows[51000].Load()
	for i := 0; i < boundaryFailureLimit+10; i++ {
		d.failure(f, boundaryRecord{Stage: "synthetic"}, nil, "injected")
	}
	if len(*events) != boundaryFailureLimit || d.budget.Load() != boundaryFailureLimit+10 {
		t.Fatal(len(*events), d.budget.Load())
	}
	if d.complete(96, 1) == nil || !d.incomplete.Load() {
		t.Fatal("missing byte coverage credited")
	}
}
func TestWordBoundaryLinkBeforeCopyAndRingBeforePublish(t *testing.T) {
	d, events := boundaryFixture(t)
	link := ns.NewLink()
	defer link.Close()
	detach, ok := ns.InstallBoundaryObserver(d.stack)
	if !ok {
		t.Fatal("hook busy")
	}
	defer detach()
	body := make([]byte, 128)
	fillPayloadWords(body, 96, 4, 0) // wrong stream before queue copying
	raw := integrityTestPacket(true, 51000, 0xffffffe1, 0, 24, body)
	p := gv.NewPacketBuffer(gv.PacketBufferOptions{ReserveHeaderBytes: 40, Payload: buffer.MakeWithData(body)})
	copy(p.TransportHeader().Push(20), raw[20:40])
	copy(p.NetworkHeader().Push(20), raw[:20])
	var packets gv.PacketBufferList
	packets.PushBack(p)
	link.WritePackets(packets)
	p.DecRef()
	if len(*events) != 1 || (*events)[0]["record"].(boundaryRecord).Stage != "stack_write" {
		t.Fatal(*events)
	}
	h := &wordRingObserver{inspect: d.raw}
	if !wordRingHook.CompareAndSwap(nil, h) {
		t.Fatal("hook busy")
	}
	defer wordRingHook.CompareAndSwap(h, nil)
	fillPayloadWords(raw[40:], 96, 5, 0)
	batch := newWordBoundaryBatch()
	batch.add(raw, 128, 0)
	// A subsequent copy damages the reserved slot before Tail publication.
	fillPayloadWords(raw[40:], 96, 4, 0)
	batch.publish()
	if len(*events) != 2 {
		t.Fatal(*events)
	}
	r := (*events)[1]["record"].(boundaryRecord)
	if r.Stage != "ring_publish" || r.Slot != 128 || r.Batch == 0 {
		t.Fatal(r)
	}
}
func TestWordBoundaryIngressAndUnmappedPayload(t *testing.T) {
	d, events := boundaryFixture(t)
	body := make([]byte, 128)
	fillPayloadWords(body, 95, 3, 0)
	d.raw("ring_ingress", integrityTestPacket(false, 51000, 0xfffffff1, 0, 24, body), 4096, 7, 3)
	if len(*events) != 1 || (*events)[0]["record"].(boundaryRecord).Slot != 4096 {
		t.Fatal(*events)
	}
	good := integrityTestPacket(false, 51001, 100, 0, 24, body)
	d.raw("ring_ingress", good, 0, 0, 0)
	if !d.incomplete.Load() {
		t.Fatal("missing SYN accepted")
	}
	// Confirm the parser really read the transport sequence.
	if binary.BigEndian.Uint32(good[24:]) != 100 {
		t.Fatal("bad fixture")
	}
}
