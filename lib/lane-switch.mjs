// Keeps one line's selector pointed where that line's apps belong: the line
// itself while it is up; while it is down, the first other line in priority
// order that is up and may carry other lines' traffic (see laneTarget). The
// main line's selector carries every app without a choice of its own.
// When a line comes back its selector points home again and nothing is
// closed: connections that moved stay where they are until they end, because
// closing them would break downloads and calls that were working. The window
// offers Reconnect per app for anyone who wants them back at once.
// Everything outside is injected (engine, readers, clock, log), so the
// behavior can be tested without Windows or the routing engine.
import { LineHealth } from './line-health.mjs';
import { laneTarget } from './lines.mjs';
import { hasDefaultRouteVia } from './network.mjs';

// The route table is read this often, in the background.
export const ROUTE_READ_EVERY_MS = 5000;
// A quick check (a TCP connection to a test address, bound to the line's
// adapter) runs this often while all looks well. It costs a few hundred bytes,
// about 2 MB a day, so it can run often even on a phone's data plan. Only when
// it fails does an HTTPS test through the routing engine confirm it (about
// 6 KB each).
export const QUICK_PROBE_EVERY_MS = 15_000;
// Without a quick check (the native helper isn't built), the HTTPS test runs
// this often instead, roughly 17 MB a day per line.
export const PROBE_EVERY_MS = 30_000;
// While in doubt, the HTTPS test runs this often, so a dead line is found in
// well under a minute and a returning one is trusted again soon.
export const PROBE_RETRY_MS = 5000;
// The same problem is written to the log at most this often.
const LOG_AGAIN_MS = 30_000;

export class LaneSwitch {
  constructor({
    engine,
    lineId,
    // The lines as saved, in priority order: [{ id, alias, label, strict }].
    getLines,
    // Whether another line is up, by id.
    isLineUp = () => false,
    // Ids of lines that are out of data for this period.
    exhausted = () => new Set(),
    usableAddresses,
    readDefaultRoutes,
    // Tests whether the line reaches the internet over HTTPS, through the
    // routing engine: (lineId, { both }) => true (or the round trip in ms),
    // false, or null when the test couldn't be run.
    probe = null,
    // The quick check, bound to the line's adapter: (line) => the connect time
    // in ms, false, or null when it couldn't be run. Optional.
    quickProbe = null,
    // Whether internet traffic is arriving or leaving through this line right
    // now. A line busy with a big transfer can be too slow to answer a test in
    // time, and its traffic already proves it works.
    carryingTraffic = () => false,
    // Told when the line goes down or comes back: ({ up, reason }).
    onChange = () => {},
    log = () => {},
    now = Date.now,
  }) {
    this.engine = engine;
    this.lineId = lineId;
    this.getLines = getLines;
    this.isLineUp = isLineUp;
    this.exhausted = exhausted;
    this.usableAddresses = usableAddresses;
    this.readDefaultRoutes = readDefaultRoutes;
    this.probe = probe;
    this.quickProbe = quickProbe;
    this.carryingTraffic = carryingTraffic;
    this.onChange = onChange;
    this.log = log;
    this.now = now;
    this.health = new LineHealth();
    this.alias = null;
    // The line id the selector points at, as far as this program knows, or
    // null before routing is on and after an answer was lost.
    this.target = null;
    // Counts routing restarts and changes of adapter. An answer that was on
    // its way from before one of those is ignored.
    this.generation = 0;
    this.routeReading = null;
    this.routeReadAt = null;
    this.probing = null;
    this.probeAt = null;
    // The last passing test's round trip in ms, for the window.
    this.delay = null;
    this.lastLogged = new Map();
    this.queue = Promise.resolve();
  }

  line() {
    return this.getLines().find((line) => line.id === this.lineId) ?? null;
  }

  name() {
    return this.line()?.label ?? 'a line';
  }

  // Routing started, stopped or restarted, or the line's adapter changed: the
  // selector is new. sameLine: still the same adapter (routing restarted), so
  // a line known to reach nothing, or still waiting for its first passing test
  // after coming back, stays down until its tests pass, instead of getting
  // traffic back meanwhile.
  reset({ sameLine = false } = {}) {
    const { offline, awaitingPass } = this.health;
    this.generation += 1;
    this.target = null;
    if (sameLine) this.health.restartKeeping({ offline, awaitingPass }, this.now());
    else this.health.reset();
    this.routeReadAt = null;
    this.probeAt = null;
    this.delay = null;
  }

  // Whether the line's own apps are on it now.
  get home() {
    return this.target === this.lineId;
  }

  logSometimes(key, line) {
    const now = this.now();
    const last = this.lastLogged.get(key);
    if (last !== undefined && now - last < LOG_AGAIN_MS) return;
    this.lastLogged.set(key, now);
    this.log(line);
  }

  // Tests run only while routing is on with this line and another one: the
  // HTTPS test goes through the engine, and with one line there is nowhere
  // else to send its apps anyway. A line out of data isn't tested, so it uses
  // no more of it.
  canTest() {
    const lines = this.engine.startedWith?.lines ?? [];
    return (
      Boolean(this.probe) &&
      this.engine.status === 'on' &&
      lines.length > 1 &&
      lines.some((line) => line.id === this.lineId) &&
      !this.exhausted().has(this.lineId)
    );
  }

  // One look at the line; called once per poll, also while routing is off,
  // because the window shows whether it is connected.
  sample() {
    const alias = this.line()?.alias ?? null;
    if (alias !== this.alias) {
      this.alias = alias;
      this.reset();
    }
    if (!alias) return false;
    let addresses;
    try {
      addresses = this.usableAddresses(alias);
    } catch (error) {
      // A reading that fails says nothing about the line.
      this.logSometimes('addresses', `could not read the network addresses: ${error.message}`);
      return this.health.up === true;
    }
    const now = this.now();
    const before = this.health.up;
    const recoveredBefore = this.health.recoveredAt;
    const up = this.health.check(addresses.length > 0, now, { tested: this.canTest() });
    if (before !== null && before !== up) {
      this.log(up ? `${this.name()} is up again` : `${this.name()} is down (${this.health.reason})`);
      try {
        this.onChange({ up, reason: this.health.reason });
      } catch {
        // Whoever listens must not break the polls.
      }
    }
    // The address just came back: look at the route table and test the line
    // at once, not at the next scheduled time, since it stays down until then.
    if (this.health.recoveredAt !== recoveredBefore) {
      this.routeReadAt = null;
      this.probeAt = null;
    }
    this.readRoutesSometimes(alias, now);
    if (addresses.length > 0) this.probeSometimes(now);
    return up === true;
  }

  isUp() {
    // The window asks between polls: a new connection is judged at once.
    if (this.health.up === null || this.line()?.alias !== this.alias) this.sample();
    return this.health.up === true;
  }

  // Reads the route table in the background. A read that fails says nothing.
  readRoutesSometimes(alias, now) {
    if (this.routeReading || (this.routeReadAt !== null && now - this.routeReadAt < ROUTE_READ_EVERY_MS)) return;
    this.routeReadAt = now;
    const generation = this.generation;
    this.routeReading = (async () => {
      try {
        const routes = await this.readDefaultRoutes();
        if (generation !== this.generation) return;
        const addresses = this.usableAddresses(alias);
        // Without an address there is nothing to look for; the address check covers that.
        this.health.noteRoute(addresses.length > 0 ? hasDefaultRouteVia(routes, addresses) : null, now);
      } catch {
        // The read failed: nothing learned.
      } finally {
        this.routeReading = null;
      }
    })();
  }

  // Tests the line's internet in the background. While all looks well, the
  // quick check runs and the HTTPS test only confirms a failed one; while in
  // doubt (a failed test, a line down for lack of internet, or one that just
  // came back), only the HTTPS test counts, asking both addresses at once.
  probeSometimes(now) {
    if (!this.canTest()) return;
    const doubt = this.health.inDoubt();
    const quick = this.quickProbe && !doubt;
    const wait = doubt ? PROBE_RETRY_MS : quick ? QUICK_PROBE_EVERY_MS : PROBE_EVERY_MS;
    if (this.probing || (this.probeAt !== null && now - this.probeAt < wait)) return;
    this.probeAt = now;
    const generation = this.generation;
    const line = this.line();
    this.probing = (async () => {
      try {
        let result = null;
        if (quick) {
          result = await this.quickProbe(line).catch(() => null);
          if (generation !== this.generation) return;
        }
        // No quick check, or it didn't pass: the HTTPS test decides.
        if (result === null || result === false) {
          result = await this.probe(this.lineId, { both: doubt });
          if (generation !== this.generation) return;
        }
        // A passing test may say how long the round trip took.
        let ok = typeof result === 'number' ? true : result;
        if (ok !== null && ok !== undefined) this.delay = typeof result === 'number' ? Math.round(result) : null;
        // A failed test on a line that is busy carrying internet traffic says
        // the line is slow, not dead: it counts neither way. A line that is
        // down carries next to nothing, so this never keeps a dead line up.
        if (ok === false && this.carryingTraffic()) {
          this.logSometimes('probe-busy', `${this.name()} didn't answer an internet test in time, but it is carrying traffic, so it still counts as working`);
          ok = null;
        }
        if (ok === false && !this.health.offline) {
          this.logSometimes('probe', `${this.name()} didn't reach the internet in a test`);
        }
        this.health.noteProbe(ok, now);
      } catch {
        // The test couldn't be run: nothing learned.
      } finally {
        this.probing = null;
      }
    })();
  }

  // The line id the selector belongs on now, or null when routing doesn't
  // have this line (it was added since routing started). Only lines routing
  // was started with have outbounds in its selectors.
  wanted() {
    const started = new Set((this.engine.startedWith?.lines ?? []).map((line) => line.id));
    if (!started.has(this.lineId)) return null;
    const lines = this.getLines().filter((line) => started.has(line.id));
    const up = (id) => (id === this.lineId ? this.isUp() : this.isLineUp(id));
    return laneTarget(lines, this.lineId, up, this.exhausted());
  }

  // Points the selector where it belongs. One at a time: the poll and the
  // engine start both call this.
  tick() {
    const run = () => this.tickNow();
    const result = this.queue.then(run, run);
    this.queue = result.catch(() => {});
    return result;
  }

  async tickNow() {
    const engine = this.engine;
    // Selectors exist only while routing runs with two lines or more.
    if (engine.status !== 'on' || (engine.startedWith?.lines?.length ?? 0) < 2) return;
    const generation = this.generation;
    const wanted = this.wanted();
    if (wanted === null || wanted === this.target) return;
    try {
      await engine.pointLaneAt(this.lineId, wanted);
    } catch (error) {
      if (generation !== this.generation) return;
      // The engine may have switched even though its answer didn't arrive:
      // from here on the position is unknown, so the next tick sets it again.
      this.target = null;
      this.logSometimes('switch', `could not point ${this.name()}'s apps at another line: ${error.message}`);
      return;
    }
    // Routing may have restarted while the engine was answering.
    if (generation !== this.generation || engine.status !== 'on') return;
    this.target = wanted;
    this.log(`${this.name()}'s apps now use ${this.getLines().find((line) => line.id === wanted)?.label ?? wanted}`);
  }
}
