package udp

import (
	"crypto/sha256"
	"encoding/hex"
	"net/netip"
	"sync"

	"github.com/AyoubAchour/net-switch/internal/engine/packet"
)

// Fixed memory, and no payload or process data retained. A payload digest
// distinguishes new sockets reusing a refused local port from repeated reads
// of the same client attempt. Only refusal paths pay for hashing.
const refusalEvidenceLimit = 256

// RefusalStatsBudget reserves room in the shared stats reply for the full
// ring at maximum address and counter widths; tested beside the recorder.
const RefusalStatsBudget = 96 << 10

type refusalEvidence struct {
	Sequence      uint64         `json:"sequence"`
	Source        netip.AddrPort `json:"source"`
	Destination   netip.AddrPort `json:"destination"`
	PayloadSHA256 string         `json:"payloadSHA256"`
	Reason        string         `json:"reason"`
	Path          string         `json:"path"`
	Sent          bool           `json:"sent"`
}

type refusalLog struct {
	mu         sync.Mutex
	count      uint64
	portSetups uint64
	recent     [refusalEvidenceLimit]refusalEvidence
}

type RefusalStats struct {
	Count                uint64            `json:"count"`
	PortExhaustionSetups uint64            `json:"portExhaustionSetups"`
	Recent               []refusalEvidence `json:"recent"`
}

func (n *NAT) RefusalStats() RefusalStats {
	n.refusals.mu.Lock()
	defer n.refusals.mu.Unlock()
	r := RefusalStats{Count: n.refusals.count, PortExhaustionSetups: n.refusals.portSetups}
	for i := n.refusals.count - min(n.refusals.count, refusalEvidenceLimit); i < n.refusals.count; i++ {
		r.Recent = append(r.Recent, n.refusals.recent[i%refusalEvidenceLimit])
	}
	return r
}

func (n *NAT) refuseDatagram(source, destination netip.AddrPort, payload, original []byte, mtu uint32, reason, path string) {
	if reason == "" {
		reason = "unclassified"
	}
	if mtu != 0 {
		reason = "message-too-large"
	}
	hash := sha256.Sum256(payload)
	n.refusals.mu.Lock()
	n.refusals.count++
	index := (n.refusals.count - 1) % refusalEvidenceLimit
	n.refusals.recent[index] = refusalEvidence{
		Sequence: n.refusals.count, Source: source, Destination: destination,
		PayloadSHA256: hex.EncodeToString(hash[:]), Reason: reason, Path: path,
	}
	// Send only enqueues output; keep stats readers behind its result so a
	// dropped output cannot be credited for an unrelated client reset.
	n.refusals.recent[index].Sent = n.out.Send(packet.Unreachable(original, mtu))
	n.refusals.mu.Unlock()
}
