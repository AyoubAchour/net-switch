// Keeps one lane's selector pointed at the right outbound: its own line while
// that line is up, the other line while it is down. There are two lanes:
// - 'second': the apps moved to the second connection. They use the cable
//   while the second connection is down.
// - 'main': everything else. It uses the second connection while the cable is
//   down, as long as the second connection is up.
// When a line comes back, this also closes the connections that were opened on
// the other line in the meantime, because a selector never moves a connection
// that is already open.
// Everything outside is injected (engine, readers, clock, log), so the
// behavior can be tested without Windows or the routing engine.
import { MAIN_LANE_SELECTOR, MAIN_OUTBOUND, SECOND_LANE_SELECTOR, SECOND_OUTBOUND } from './apps.mjs';
import { LineHealth } from './line-health.mjs';
import { hasDefaultRouteVia } from './network.mjs';

// The route table is read this often, in the background.
export const ROUTE_READ_EVERY_MS = 5000;
// The line's internet is tested this often while all looks well, and sooner
// while in doubt, so a dead line is found in under a minute. Each test is a
// small HTTPS request (about 6 KB), so this is roughly 17 MB a day per line,
// which matters on a phone's data plan.
export const PROBE_EVERY_MS = 30_000;
export const PROBE_RETRY_MS = 5000;
// After a line returns, give it this long to settle before the stuck
// connections are closed, so a flapping line doesn't cause repeated resets.
export const RELEASE_SETTLE_MS = 2000;
// A close that left connections behind is tried again this often, this many times in all.
export const RELEASE_RETRY_MS = 5000;
export const RELEASE_ATTEMPTS = 3;
// The same problem is written to the log at most this often.
const LOG_AGAIN_MS = 30_000;

const LANES = {
  second: {
    selector: SECOND_LANE_SELECTOR,
    home: SECOND_OUTBOUND,
    away: MAIN_OUTBOUND,
    name: 'second connection',
    awayName: 'cable',
    switchName: 'second lane',
    apps: 'second-lane apps',
  },
  main: {
    selector: MAIN_LANE_SELECTOR,
    home: MAIN_OUTBOUND,
    away: SECOND_OUTBOUND,
    name: 'cable',
    awayName: 'second connection',
    switchName: 'cable lane',
    apps: 'cable apps',
  },
};

export class LaneSwitch {
  constructor({
    engine,
    lane = 'second',
    getAlias,
    // Whether the other line is up: the cable's apps only move to the second
    // connection when it can carry them.
    otherIsUp = () => true,
    usableAddresses,
    readDefaultRoutes,
    // Tests whether the line reaches the internet: (outbound) => true, false,
    // or null when the test couldn't be run. Without one, only the address and
    // route say whether the line is up.
    probe = null,
    runExclusive = (task) => task(),
    log = () => {},
    now = Date.now,
  }) {
    this.engine = engine;
    this.lane = lane;
    this.names = LANES[lane];
    this.getAlias = getAlias;
    this.otherIsUp = otherIsUp;
    this.usableAddresses = usableAddresses;
    this.readDefaultRoutes = readDefaultRoutes;
    this.probe = probe;
    this.runExclusive = runExclusive;
    this.log = log;
    this.now = now;
    this.health = new LineHealth();
    this.alias = null;
    // Where the selector points, as far as this program knows: the lane's own
    // outbound, the other one, or null before routing is on and after an
    // answer was lost.
    this.target = null;
    // Counts routing restarts and changes of connection. An answer that was on
    // its way from before one of those is ignored.
    this.generation = 0;
    // The selector may have pointed at the other line since the last complete
    // close. It is set even when the engine's answer was lost, because the
    // engine may have switched anyway.
    this.awaySince = false;
    this.releaseAt = null;
    this.releaseAttempts = 0;
    this.recovery = { closed: 0, failed: 0 };
    this.releasing = null;
    this.releaseAgain = false;
    this.routeReading = null;
    this.routeReadAt = null;
    this.probing = null;
    this.probeAt = null;
    // The last passing internet test's round trip in ms, for the window.
    this.delay = null;
    // What closing did, for the window: { closed, failed, at }.
    this.lastRelease = null;
    this.lastLogged = new Map();
    this.queue = Promise.resolve();
  }

  // Routing started, stopped or restarted, or another connection was chosen:
  // the selector is new and nothing is stuck. sameLine: still the same line
  // (routing restarted), so a line known to reach nothing stays down until
  // its tests pass again, instead of getting traffic back meanwhile.
  reset({ sameLine = false } = {}) {
    const offline = sameLine && this.health.offline;
    this.generation += 1;
    this.target = null;
    this.awaySince = false;
    this.releaseAt = null;
    this.releaseAttempts = 0;
    this.recovery = { closed: 0, failed: 0 };
    this.releaseAgain = false;
    // A release still waiting from before belongs to the old generation; the
    // next request must start its own.
    this.releasing = null;
    this.lastRelease = null;
    this.health.reset();
    this.health.offline = offline;
    this.routeReadAt = null;
    this.probeAt = null;
    this.delay = null;
  }

  // Whether the lane is on its own line now.
  get home() {
    return this.target === this.names.home;
  }

  logSometimes(key, line) {
    const now = this.now();
    const last = this.lastLogged.get(key);
    if (last !== undefined && now - last < LOG_AGAIN_MS) return;
    this.lastLogged.set(key, now);
    this.log(line);
  }

  // One look at the line; called once per poll, also while routing is off,
  // because the window shows whether it is connected.
  sample() {
    const alias = this.getAlias();
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
    const up = this.health.check(addresses.length > 0, now);
    if (before !== null && before !== up) {
      this.log(up ? `${this.names.name} is up again` : `${this.names.name} is down (${this.health.reason})`);
    }
    // The address just came back: look at the route table at once, not at the
    // next scheduled read, because closing connections waits for that reading.
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
    if (this.health.up === null || this.getAlias() !== this.alias) this.sample();
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

  // Tests the line's internet in the background, through the line's own
  // outbound, so it only runs while routing is on. Without a second
  // connection there is no other line to fall back to, so nothing is tested.
  probeSometimes(now) {
    const engine = this.engine;
    if (!this.probe || engine.status !== 'on' || !engine.startedWith?.secondAlias) return;
    // Sooner while in doubt: after a failed test, and while the line is down
    // for lack of internet, so it is back as soon as two tests pass.
    const wait = this.health.probeFails > 0 || this.health.offline ? PROBE_RETRY_MS : PROBE_EVERY_MS;
    if (this.probing || (this.probeAt !== null && now - this.probeAt < wait)) return;
    this.probeAt = now;
    const generation = this.generation;
    this.probing = (async () => {
      try {
        const result = await this.probe(this.names.home);
        if (generation !== this.generation) return;
        // A passing test may say how long the round trip took.
        const ok = typeof result === 'number' ? true : result;
        if (ok !== null && ok !== undefined) this.delay = typeof result === 'number' ? Math.round(result) : null;
        if (ok === false && !this.health.offline) {
          this.logSometimes('probe', `${this.names.name} didn't reach the internet in a test`);
        }
        this.health.noteProbe(ok, now);
      } catch {
        // The test couldn't be run: nothing learned.
      } finally {
        this.probing = null;
      }
    })();
  }

  // Where the selector belongs now.
  wanted() {
    const { home, away } = this.names;
    if (this.lane === 'second') return this.isUp() ? home : away;
    // The cable's traffic only leaves the cable for a second connection that works.
    return this.isUp() || !this.otherIsUp() ? home : away;
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
    // Both selectors exist only while routing runs with a second connection.
    if (engine.status !== 'on' || !engine.startedWith?.secondAlias) return;
    const generation = this.generation;
    const { home, away, selector } = this.names;
    const wanted = this.wanted();
    if (wanted !== this.target) {
      if (wanted === away) this.awaySince = true;
      try {
        await engine.pointLaneAt(selector, wanted);
      } catch (error) {
        if (generation !== this.generation) return;
        // The engine may have switched even though its answer didn't arrive:
        // from here on the position is unknown, so the next tick sets it again.
        this.target = null;
        this.logSometimes('switch', `could not switch ${this.names.switchName}: ${error.message}`);
        return;
      }
      // Routing may have restarted while the engine was answering.
      if (generation !== this.generation || engine.status !== 'on') return;
      this.target = wanted;
      this.log(`${this.names.apps} now use ${wanted}`);
      if (wanted === home && this.awaySince) {
        this.releaseAt = this.now() + RELEASE_SETTLE_MS;
        this.releaseAttempts = 0;
        this.recovery = { closed: 0, failed: 0 };
      } else if (wanted === away) {
        this.releaseAt = null;
      }
      return;
    }
    if (this.releaseAt !== null && this.target === home && this.now() >= this.releaseAt) {
      // The line may be about to drop again (a poll without an address, a
      // route reading without a default route, or a failed internet test):
      // keep waiting. If it does drop, the lane goes back to the other line
      // and this request ends there.
      if (this.health.shaky(this.now())) return;
      this.releaseAt = null;
      this.startRelease();
    }
  }

  // In the background: closing can take seconds, and the poll must go on. A
  // second request while one is waiting or running runs again right after it,
  // because those connections may have been opened after the first one looked.
  // A worker from before a reset doesn't count: it ends as soon as it notices.
  startRelease() {
    if (this.releasing && this.releasingGeneration === this.generation) {
      this.releaseAgain = true;
      return;
    }
    const generation = this.generation;
    this.releasingGeneration = generation;
    const worker = (async () => {
      try {
        do {
          this.releaseAgain = false;
          try {
            await this.runExclusive(() => this.releaseNow(generation));
          } catch (error) {
            if (generation === this.generation) {
              this.log(`could not move connections back to the ${this.names.name}: ${error.message}`);
              this.retryRelease();
            }
          }
        } while (this.releaseAgain && generation === this.generation);
      } finally {
        if (this.releasing === worker) this.releasing = null;
      }
    })();
    this.releasing = worker;
  }

  async releaseNow(generation) {
    const current = () => generation === this.generation && this.home && this.engine.status === 'on';
    if (!current()) return;
    // Closing goes on only while the line looks healthy, poll after poll.
    const keepGoing = () => current() && this.health.up === true && !this.health.shaky(this.now());
    let result;
    try {
      result = await this.engine.releaseFallbackConnections({ lane: this.lane, shouldContinue: keepGoing });
    } catch (error) {
      if (!current()) return;
      this.log(`could not move connections back to the ${this.names.name}: ${error.message}`);
      this.retryRelease();
      return;
    }
    if (!current()) return;
    this.recovery.closed += result.closed;
    this.recovery.failed = result.failed;
    if (result.closed + result.failed > 0) {
      this.lastRelease = { closed: this.recovery.closed, failed: this.recovery.failed, at: this.now() };
      this.log(
        `${this.names.name} is back: closed ${result.closed} connection${result.closed === 1 ? '' : 's'} that had moved to the ${this.names.awayName}` +
          (result.failed > 0 ? `, ${result.failed} could not be closed` : ''),
      );
    }
    if (result.interrupted || result.failed > 0) {
      this.retryRelease();
      return;
    }
    // Everything that was stuck is closed.
    this.awaySince = false;
  }

  // Tries again soon for what was left behind, a few times at most. After that
  // the connections stay where they are, as they did before this existed.
  retryRelease() {
    this.releaseAttempts += 1;
    if (this.releaseAttempts >= RELEASE_ATTEMPTS) {
      this.log(`gave up moving the rest of the connections back to the ${this.names.name}`);
      return;
    }
    this.releaseAt = this.now() + RELEASE_RETRY_MS;
  }
}
