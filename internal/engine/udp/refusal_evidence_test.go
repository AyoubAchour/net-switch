package udp

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/netip"
	"testing"
	"time"

	"github.com/AyoubAchour/net-switch/internal/engine/packet"
	"github.com/AyoubAchour/net-switch/internal/engine/platform"
	"github.com/AyoubAchour/net-switch/internal/engine/testfake"
)

func TestRefusalEvidenceReusedSourcesRetainExhaustionCause(t *testing.T) {
	n, _, _, out, _, calls := setup(t, &testfake.Owners{Value: owner})
	n.now = func() time.Time { return time.Unix(1, 0) }
	n.dialer = testfake.Dialer{UDPFunc: func(context.Context, string, bool) (platform.UDPConn, error) {
		calls.Add(1)
		return nil, fmt.Errorf("bind: %w", platform.ErrPortExhausted)
	}}
	for i := range 78 {
		source := netip.AddrPortFrom(local.Addr(), uint16(40000+i%20))
		payload := []byte(fmt.Sprintf("attempt-%d", i))
		n.receive(source, dest, 64, func() ([]byte, []byte, bool) { return payload, packet.UDP(source, dest, payload), false })
		await(t, out)
		if i < 20 {
			// Assert the original setup was cached, then finish closing it;
			// subsequent attempts must take the negative-cache path itself.
			b := n.bucket(source)
			b.Lock()
			s := b.m[source]
			entry, ok := b.negative[source]
			b.Unlock()
			if !ok || entry.reason != "port-exhaustion" {
				t.Fatal("fixture has no exhausted cache entry")
			}
			if s != nil {
				s.close()
			}
		}
	}
	stats := n.RefusalStats()
	if calls.Load() != 20 || stats.PortExhaustionSetups != 20 || stats.Count != 78 || len(stats.Recent) != 78 {
		t.Fatalf("binds=%d, refusal stats=%+v", calls.Load(), stats)
	}
	for i, r := range stats.Recent {
		hash := sha256.Sum256([]byte(fmt.Sprintf("attempt-%d", i)))
		path := "pending"
		if i >= 20 {
			path = "negative-cache"
		}
		if r.Sequence != uint64(i+1) || !r.Sent || r.Reason != "port-exhaustion" || r.Path != path || r.PayloadSHA256 != hex.EncodeToString(hash[:]) {
			t.Fatalf("attempt %d lost its own evidence: %+v", i, r)
		}
	}
	t.Log("78 datagram refusals = 20 exhausted setups + 58 cached replies on reused sources; each has its own digest")
}

func TestRefusalEvidenceIsBoundedAndDoesNotStorePayload(t *testing.T) {
	n := &NAT{out: testfake.Output{}}
	source := netip.MustParseAddrPort("[ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff]:65535")
	for range refusalEvidenceLimit * 2 {
		n.refuseDatagram(source, source, []byte("private payload"), nil, 0, "policy-or-owner-budget", "rejected-session")
	}
	r := n.RefusalStats()
	wide := r
	wide.Count, wide.PortExhaustionSetups = ^uint64(0), ^uint64(0)
	wide.Recent = append([]refusalEvidence(nil), r.Recent...)
	for i := range wide.Recent {
		wide.Recent[i].Sequence = ^uint64(0) - uint64(i)
	}
	b, err := json.Marshal(wide)
	if err != nil || r.Count != 512 || len(r.Recent) != 256 || r.Recent[0].Sequence != 257 || len(b) > RefusalStatsBudget || bytes.Contains(b, []byte("private payload")) {
		t.Fatalf("unbounded refusal history: count=%d recent=%d bytes=%d err=%v", r.Count, len(r.Recent), len(b), err)
	}
	t.Logf("maximum retained refusal evidence: %d bytes", len(b))
}

// Refusal instrumentation never runs on successful sends. Measure its cost
// against the old ICMP path using the acceptance probe's 16-byte datagram.
func BenchmarkRefusalEvidence(b *testing.B) {
	payload := []byte("NSUDPCAP12345678")
	original := packet.UDP(local, dest, payload)
	for _, record := range []bool{false, true} {
		b.Run(fmt.Sprintf("record=%t", record), func(b *testing.B) {
			n := &NAT{out: testfake.Output{}}
			b.ReportAllocs()
			for b.Loop() {
				if record {
					n.refuseDatagram(local, dest, payload, original, 0, "port-exhaustion", "negative-cache")
				} else {
					n.out.Send(packet.Unreachable(original, 0))
				}
			}
		})
	}
}
