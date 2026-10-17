// Decides whether a line is up. Each reading can be wrong for a moment, so a
// reading that failed or is missing never counts as "down" by itself, and a
// drop has to repeat before routing falls back to another line.
// Pure: the caller passes the readings and the clock.

// Polls in a row (about a second apart) without a usable address.
export const ADDRESS_MISSES_TO_FAIL = 2;
// Route reads in a row (about five seconds apart) that worked but showed no default route.
export const ROUTE_MISSES_TO_FAIL = 2;
// A route reading older than this says nothing about the line now.
export const ROUTE_STALE_MS = 30_000;
// Two polls closer than this count as one, so several callers can't double count.
export const MIN_POLL_GAP_MS = 400;
// A line can keep its address and route and still reach nothing: a phone whose
// mobile data is off, or a router whose own internet is down. Internet tests
// in a row that failed before that counts as down, and that passed before it
// counts as back. Tests that couldn't be run count neither way.
export const PROBE_FAILS_TO_FAIL = 3;
export const PROBE_PASSES_TO_RECOVER = 2;
// A line whose address has just come back often has no internet yet (a phone
// reconnecting, a router still starting), so while lines are tested it stays
// down until a test passes. When no test could be run at all for this long,
// it is trusted on its address alone, as it would be without tests.
export const PASS_WAIT_MS = 30_000;

export class LineHealth {
  constructor() {
    this.reset();
  }

  reset() {
    // null until the first poll, then true or false.
    this.up = null;
    this.hadAddress = null;
    this.addressMisses = 0;
    this.routeMisses = 0;
    this.route = null;
    // When the address last came back after missing, if it did.
    this.recoveredAt = null;
    this.lastPollAt = null;
    this.resetProbes();
    // Why the line is down, for the log.
    this.reason = null;
  }

  resetProbes() {
    this.probeFails = 0;
    this.probePasses = 0;
    // Set by repeated failed internet tests, cleared by repeated passes.
    this.offline = false;
    // Set when the address comes back, cleared by the first passing test.
    this.awaitingPass = false;
  }

  // Tests should come sooner, and only the thorough kind counts: the last one
  // failed, the line is down for lack of internet, or it is waiting for a
  // first pass after coming back.
  inDoubt() {
    return this.probeFails > 0 || this.offline || this.awaitingPass;
  }

  // ok: whether an internet test through this line passed, or null when it
  // couldn't be run. now is when the test started: one from before the address
  // came back describes the outage.
  noteProbe(ok, now) {
    if (ok === null || ok === undefined) return;
    if (this.recoveredAt !== null && now < this.recoveredAt) return;
    if (ok) {
      this.probeFails = 0;
      this.probePasses += 1;
      this.awaitingPass = false;
      if (this.offline && this.probePasses >= PROBE_PASSES_TO_RECOVER) this.offline = false;
    } else {
      this.probePasses = 0;
      this.probeFails += 1;
      if (this.probeFails >= PROBE_FAILS_TO_FAIL) this.offline = true;
    }
  }

  // present: true when a default route uses this line, false when the read
  // worked and found none, null when the read failed (which says nothing).
  // now is when the read started: a read that began before the address came
  // back describes the outage, whenever it ends.
  noteRoute(present, now) {
    if (present === null || present === undefined) return;
    if (this.recoveredAt !== null && now < this.recoveredAt) return;
    // Misses count only while they follow each other: after a long gap, or with
    // no earlier reading at all, the old ones are forgotten.
    if (this.route === null || now - this.route.at > ROUTE_STALE_MS) this.routeMisses = 0;
    this.route = { present, at: now };
    this.routeMisses = present ? 0 : this.routeMisses + 1;
  }

  // One poll. Returns whether the line counts as up. tested: whether internet
  // tests run for this line now; without them a returning line can't be
  // asked to pass one.
  check(hasAddress, now, { tested = false } = {}) {
    if (this.lastPollAt !== null && now - this.lastPollAt < MIN_POLL_GAP_MS) return this.up;
    this.lastPollAt = now;

    // A route reading or internet test from before the address came back
    // describes the outage, not the line now: they are forgotten together.
    if (this.hadAddress === false && hasAddress) {
      this.route = null;
      this.routeMisses = 0;
      this.resetProbes();
      this.recoveredAt = now;
      this.awaitingPass = this.up === false;
    }
    this.hadAddress = hasAddress;
    this.addressMisses = hasAddress ? 0 : this.addressMisses + 1;
    // No test has been able to say anything for a while: go on without one.
    if (this.awaitingPass && this.probeFails === 0 && now - this.recoveredAt >= PASS_WAIT_MS) this.awaitingPass = false;

    const routeKnown = this.route !== null && now - this.route.at <= ROUTE_STALE_MS;
    const routeMissing = routeKnown && !this.route.present;
    const waiting = tested && this.awaitingPass;
    const clean = hasAddress && !routeMissing && !this.offline && !waiting;

    if (this.up === null) {
      // The first reading counts at once: there is no earlier state to protect.
      this.up = hasAddress && !routeMissing && !this.offline;
      this.reason = this.up ? null : !hasAddress ? 'no address' : routeMissing ? 'no default route' : 'no internet';
    } else if (this.up) {
      if (this.addressMisses >= ADDRESS_MISSES_TO_FAIL) {
        this.up = false;
        this.reason = 'no address';
      } else if (routeMissing && this.routeMisses >= ROUTE_MISSES_TO_FAIL) {
        this.up = false;
        this.reason = 'no default route';
      } else if (this.offline) {
        this.up = false;
        this.reason = 'no internet';
      }
    } else if (clean) {
      this.up = true;
      this.reason = null;
    } else {
      // Still down: say why now. 'checking' means connected again, and only
      // the first passing test is missing.
      this.reason = !hasAddress ? 'no address' : routeMissing ? 'no default route' : this.offline ? 'no internet' : 'checking';
    }
    return this.up;
  }
}
