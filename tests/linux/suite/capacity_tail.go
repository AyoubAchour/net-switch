//go:build linux

package suite

import (
	"strconv"
	"time"

	"github.com/AyoubAchour/net-switch/tests/linux/app"
	"github.com/AyoubAchour/net-switch/tests/linux/wire"
)

const capacityTailAttempts = 100
const capacityTailKey = "kilo-tail"

// Begin reserves total capacity before owner lookup. At the end of a fully
// concurrent offer, a last lookup can be refused by the separate unknown
// pool after other apps have already received their total-cap refusals.
// A fixed sequential tail measures the held cap after those reservations
// settle. It always runs, even when the burst already filled every slot.
// It never retries an attempt, loops until full, or weakens the exact cap.
// base is what the clients independently hold once the burst settles.
func (e *Env) capacityTail(release Release, apps map[string]*Bg, held map[string]app.HeldList, base heldBase) int {
	_, s := e.v1()
	deadline := time.Now().Add(15 * time.Second)
	before := stats(e, s)
	for before.Handshakes != 0 && time.Now().Before(deadline) {
		e.Sleep(20 * time.Millisecond)
		before = stats(e, s)
	}
	e.T.Require(before.Handshakes == 0, "burst admissions have settled before the fixed tail (%d pending)", before.Handshakes)
	e.T.Logf("CAP PREFIX: flows=%d UDP=%d peak=%d unknown=%d lookups=%d misses=%d; original burst-only held-cap verdict=%t; original attribution verdict=%t; original reservation-cap verdict=%t",
		before.Flows, before.UDP, before.PeakFlows, before.Unknown, before.LookupCount, before.LookupMisses,
		before.Flows == tcpFlowsTotal, before.LookupCount > 0 && before.LookupMisses*200 <= before.LookupCount, before.PeakFlows == tcpFlowsTotal)
	if e.deferAttribution {
		e.T.ReleaseCheck(before.LookupCount > 0 && before.LookupMisses*200 <= before.LookupCount,
			"the original burst window identifies at least 99.5%% before any sequential tail can dilute it (%d misses of %d)", before.LookupMisses, before.LookupCount)
	}
	e.T.Note("Offer includes a fixed %d new sequential tail attempts after the original 80,000 concurrent attempts settle; no retries.", capacityTailAttempts)
	// Kilo has no UDP in the mixed case and at most 8,000 earlier attempts,
	// so even this complete tail remains below its 8,192 per-app ceiling.
	bg := e.Start(Run{App: "kilo", Args: append([]string{"tcphold", "--to", floodTargets(9, wire.PortHold),
		"--count", strconv.Itoa(capacityTailAttempts), "--concurrency", "1", "--timeout", "10000", "--tuples", "--probe"}, release.Arg()...)})
	var list app.HeldList
	bg.WaitHeld(e, "held", time.Minute, &list)
	apps[capacityTailKey], held[capacityTailKey] = bg, list
	refused := list.Errors["ECONNREFUSED"] + list.Errors["ECONNRESET"]
	e.T.Check(list.Established+refused == capacityTailAttempts, "every fixed tail attempt either stays open or is explicitly refused (%d held, %d refused, errors %v)", list.Established, refused, list.Errors)
	after := e.memorySample(s, "TCP FIXED TAIL")
	e.capacityAccounting("fixed new-process tail", "tcp", before, after, base, capacityTailAttempts, list.Established, refused, capacityTotal)
	// These sockets arrive while the large held workload still exists.
	// Only proved unknown-pool failures are covered by its load declaration;
	// the separate probes after fault/load cleanup remain hard.
	e.T.ReleaseCheck(after.LookupMisses == before.LookupMisses, "the held-load tail identifies every lookup (%d misses of %d); old zero-miss verdict=%t",
		after.LookupMisses-before.LookupMisses, after.LookupCount-before.LookupCount, after.LookupMisses == before.LookupMisses)
	e.T.Logf("CAP TAIL: offered=%d held=%d refused=%d flows=%d handshakes=%d; final held-cap verdict=%t",
		capacityTailAttempts, list.Established, refused, after.Flows, after.Handshakes, after.Flows == tcpFlowsTotal)
	return list.Established
}
