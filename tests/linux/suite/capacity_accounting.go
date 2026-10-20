//go:build linux

package suite

import (
	"github.com/AyoubAchour/net-switch/internal/engine/flows"
	"github.com/AyoubAchour/net-switch/tests/linux/engine"
)

type capacityScope uint8

const (
	capacityTotal capacityScope = iota
	capacityPerApp
	capacityMixed
)

// Refusal counters count decisions; clients count completed attempts. A SYN
// whose notice was throttled can be counted again. Subtract EVERY allowed cap
// decision from client refusals, including repetitions, to get a conservative
// lower bound on distinct refusals caused by the unknown pool. Never use the
// raw unknown counter as credit for an exact-cap shortfall.
func unknownRefusalFloor(clientRefused int, r flows.Refusals, capDecisions uint64) (uint64, bool) {
	unknown := r.Unknown + r.UnknownUDP
	if clientRefused < 0 || r.Count() != capDecisions+unknown || uint64(clientRefused) > r.Count() {
		return 0, false
	}
	if uint64(clientRefused) <= capDecisions {
		return 0, true
	}
	return uint64(clientRefused) - capDecisions, true
}

// Every caller takes the two samples around exactly its offered traffic,
// before releasing any holder. A different reason, lost attempt, failed dial
// or admitted-then-lost flow fails hard even inside a declared load case.
func (e *Env) capacityAccounting(label, protocol string, before, after engine.Stats, offered, held, refused int, scope capacityScope) uint64 {
	r := after.RefusedTCP.Sub(before.RefusedTCP)
	forward := after.Counters["tcpRejected"] - before.Counters["tcpRejected"]
	capDecisions := r.Total
	if scope == capacityPerApp {
		capDecisions = r.PerApp
	} else if scope == capacityMixed {
		// UDP and TCP share the per-app flow cap. An app holding UDP may
		// legitimately fill 8,192 combined slots before the total fills.
		capDecisions += r.PerApp
	}
	if protocol == "udp" {
		r = after.RefusedUDP.Sub(before.RefusedUDP)
		forward = after.Counters["udpRejected"] - before.Counters["udpRejected"]
		capDecisions = r.UDP
		if scope == capacityPerApp {
			capDecisions = r.UDPPerApp
		}
	} else {
		e.T.Check(after.Counters["tcpDialFailed"] == before.Counters["tcpDialFailed"],
			"%s: no outbound TCP dial failed (%d)", label, after.Counters["tcpDialFailed"]-before.Counters["tcpDialFailed"])
	}
	floor, classified := unknownRefusalFloor(refused, r, capDecisions)
	occupied := (r.Total == 0 || after.PeakFlows == tcpFlowsTotal) &&
		(r.UDP == 0 || after.PeakUDP == udpSessionsTotal) &&
		(r.PerApp == 0 || after.PeakPerApp == tcpFlowsPerApp) &&
		(r.UDPPerApp == 0 || after.PeakUDPPerApp == udpSessionsPerApp) &&
		(r.Unknown == 0 || after.PeakUnknown == 2048) &&
		(r.UnknownUDP == 0 || after.PeakUnknownUDP == 512)
	e.T.Check(occupied, "%s: every reported cap refusal has an independently observed full pool", label)
	// The UDP fixture sends exactly one datagram from each fresh socket.
	// Unlike SYNs it has no transport retransmission that can repeat a decision.
	if protocol == "udp" {
		classified = classified && r.Count() == uint64(refused)
	}
	e.T.Check(offered == held+refused, "%s: every offered attempt is held or explicitly refused (%d = %d + %d)", label, offered, held, refused)
	e.T.Check(after.Admitted-before.Admitted == uint64(held),
		"%s: every admitted flow is still held (%d admitted, %d held)", label, after.Admitted-before.Admitted, held)
	e.T.Check(classified && forward == r.Count(),
		"%s: every refusal decision is at the requested cap or unknown-pool overflow (%+v; forwarding=%d, client refusals=%d, distinct unknown refusals >=%d)",
		label, r, forward, refused, floor)
	misses := after.LookupMisses - before.LookupMisses
	unknownAdmitted := after.AdmittedUnknown - before.AdmittedUnknown
	e.T.Check(misses == unknownAdmitted+r.Unknown+r.UnknownUDP,
		"%s: every missed lookup is an admitted unknown or a counted unknown-pool refusal (%d = %d + %d)",
		label, misses, unknownAdmitted, r.Unknown+r.UnknownUDP)
	e.T.Check(after.PeakFlows <= tcpFlowsTotal && after.PeakPerApp <= tcpFlowsPerApp && after.PeakHandshakes <= tcpHandshakes &&
		after.PeakUDP <= udpSessionsTotal && after.PeakUDPPerApp <= udpSessionsPerApp &&
		after.PeakUnknown <= 2048 && after.PeakUnknownUDP <= 512,
		"%s: total, per-app and unknown pools never exceed their caps (%d/%d TCP+UDP, %d/%d UDP, %d/%d unknown)",
		label, after.PeakFlows, after.PeakPerApp, after.PeakUDP, after.PeakUDPPerApp, after.PeakUnknown, after.PeakUnknownUDP)
	e.T.Check(after.Counters["runtimeBytes"] > 0 && after.Counters["runtimeBytes"] <= 512<<20,
		"%s: held memory stays within 512 MiB (%d bytes)", label, after.Counters["runtimeBytes"])
	e.T.Logf("CAP ACCOUNTING %s: offered=%d held=%d client-refused=%d decisions=%+v unknown-refusal-floor=%d lookup-misses=%d unknown-admitted=%d owner-details=%s",
		label, offered, held, refused, r, floor, misses, unknownAdmitted, after.OwnerLookup)
	if !classified || !occupied || forward != r.Count() || offered != held+refused || after.Admitted-before.Admitted != uint64(held) ||
		misses != unknownAdmitted+r.Unknown+r.UnknownUDP {
		return 0
	}
	return floor
}

func (e *Env) exactCapacity(label string, held, target int, unknownRefusals uint64) {
	old := held == target
	shortfall := max(0, target-held)
	explained := held <= target && uint64(shortfall) <= unknownRefusals
	e.T.Check(explained, "%s: the whole exact-cap shortfall is accounted for by distinct unknown-overflow refusals (%d missing, at least %d unknown refusals)", label, shortfall, unknownRefusals)
	e.T.Logf("CAP OLD VERDICT %s: held=%d target=%d old-exact-count=%t; shortfall=%d attribution-accounted=%t",
		label, held, target, old, shortfall, explained)
	if explained {
		e.T.ReleaseCheck(old, "%s reaches exactly %d (%d held, %d missing due to attribution; eBPF pending under section 5.6)", label, target, held, shortfall)
	}
}
