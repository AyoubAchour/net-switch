//go:build linux

package suite

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/AyoubAchour/net-switch/internal/engine/flows"
	"github.com/AyoubAchour/net-switch/internal/engine/platform"
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

// heldBase is what clients and servers independently held when the first
// sample was taken: live TCP connections and UDP sessions, never the engine's
// own count. A delta alone can't catch a phantom flow carried through both
// samples, so both samples must equal what is held, absolutely.
type heldBase struct{ tcp, udp int }

// streamBase is charlie's survival stream, the one flow open before the
// offered traffic. Its client's own record (keptOpen: connected, never
// closed, every answer on its line) proves it was held across both samples.
var streamBase = heldBase{tcp: 1}

// Every caller takes the two samples around exactly its offered traffic,
// before releasing any holder. A different reason, lost attempt, failed dial
// or admitted-then-lost flow fails hard even inside a declared load case.
func (e *Env) capacityAccounting(label, protocol string, before, after engine.Stats, base heldBase, offered, held, refused int, scope capacityScope, fullCombinedApp ...bool) uint64 {
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
		missing := after.Counters["udpGenerationMissing"] - before.Counters["udpGenerationMissing"]
		details := ""
		if missing != 0 {
			details = "; " + udpGenerationFailureDetails(after.OwnerLookup)
		}
		e.T.Check(after.Counters["udpGenerationMissing"] == before.Counters["udpGenerationMissing"], "%s: every UDP setup obtained a socket generation (%d missing%s)", label, missing, details)
		e.T.Check(after.Counters["udpOpenFailed"] == before.Counters["udpOpenFailed"], "%s: no native UDP open failed (%d)", label, after.Counters["udpOpenFailed"]-before.Counters["udpOpenFailed"])
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
	e.T.Check(occupied, "%s: every reported cap refusal has a matching engine peak", label)
	independentApp := scope != capacityMixed || r.PerApp == 0 || (len(fullCombinedApp) == 1 && fullCombinedApp[0])
	e.T.Check(independentApp, "%s: mixed per-app refusals require a UDP-holding client app with exactly 8192 identified TCP plus UDP sockets independently observed on its pinned line", label)
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
	e.checkCapacityMemory(label, after)
	e.T.Check(after.Flows-before.Flows == int64(held), "%s: engine flow delta equals independently held clients (%d = %d)", label, after.Flows-before.Flows, held)
	if protocol == "udp" {
		e.T.Check(after.UDP-before.UDP == int64(held), "%s: engine UDP delta equals independently held clients (%d = %d)", label, after.UDP-before.UDP, held)
	}
	baseFlows, baseUDP := int64(base.tcp+base.udp), int64(base.udp)
	wantFlows, wantUDP := baseFlows+int64(held), baseUDP
	if protocol == "udp" {
		wantUDP += int64(held)
	}
	baseline := before.Flows == baseFlows && before.UDP == baseUDP
	absolute := after.Flows == wantFlows && after.UDP == wantUDP
	e.T.Check(baseline, "%s: engine baseline equals independently observed holders (flows %d = %d TCP + %d UDP; UDP %d = %d)",
		label, before.Flows, base.tcp, base.udp, before.UDP, baseUDP)
	e.T.Check(absolute, "%s: engine absolute count equals independently held clients plus baseline holders (flows %d = %d + %d; UDP %d = %d)",
		label, after.Flows, baseFlows, held, after.UDP, wantUDP)
	delta := after.Flows-before.Flows == int64(held) && (protocol != "udp" || after.UDP-before.UDP == int64(held))
	e.T.Logf("CAP ACCOUNTING %s: offered=%d held=%d client-refused=%d decisions=%+v unknown-refusal-floor=%d lookup-misses=%d unknown-admitted=%d base-TCP=%d base-UDP=%d old-delta-verdict=%t baseline-verdict=%t absolute-verdict=%t owner-details=%s",
		label, offered, held, refused, r, floor, misses, unknownAdmitted, base.tcp, base.udp, delta, baseline, absolute, after.OwnerLookup)
	if !classified || !occupied || !independentApp || !delta || !baseline || !absolute || forward != r.Count() || offered != held+refused || after.Admitted-before.Admitted != uint64(held) ||
		misses != unknownAdmitted+r.Unknown+r.UnknownUDP {
		return 0
	}
	return floor
}

// The engine retains eight failures. Surface that bounded history beside the
// exact assertion; LastError may already describe an unrelated holder timeout.
func udpGenerationFailureDetails(raw json.RawMessage) string {
	var lookup struct {
		UDPGenerationFailures []struct {
			Tuple        platform.Tuple
			Stage, Error string
			Errno        int
			Query        *struct {
				Stage                         string
				StartedNS, DeadlineNS, SentNS int64
				ReplyErrno                    int32
			}
		}
	}
	if err := json.Unmarshal(raw, &lookup); err != nil {
		return fmt.Sprintf("UDPGenerationFailures unavailable: %v", err)
	}
	var details []string
	for _, f := range lookup.UDPGenerationFailures[:min(8, len(lookup.UDPGenerationFailures))] {
		query := "query=none"
		if q := f.Query; q != nil {
			lag := "unbounded"
			if q.DeadlineNS != 0 {
				lag = time.Duration(q.StartedNS - q.DeadlineNS).String()
			}
			query = fmt.Sprintf("query-stage=%s query-start-after-deadline=%s sent=%t reply-errno=%d", q.Stage, lag, q.SentNS != 0, q.ReplyErrno)
		}
		details = append(details, fmt.Sprintf("tuple=%s->%s stage=%s %s errno=%d error=%q", f.Tuple.Source, f.Tuple.Destination, f.Stage, query, f.Errno, f.Error))
	}
	return "UDPGenerationFailures=[" + strings.Join(details, "; ") + "]"
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
