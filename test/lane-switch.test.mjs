import assert from 'node:assert/strict';
import { test } from 'node:test';
import { LaneSwitch } from '../lib/lane-switch.mjs';

const WIFI = '192.168.1.21';
const ROUTES = [
  { gateway: '192.168.1.1', interfaceAddress: '192.168.1.11', metric: 35 },
  { gateway: '192.168.1.1', interfaceAddress: WIFI, metric: 55 },
];

const CABLE = '192.168.1.11';

// A PC with a second connection, a routing engine and a clock we move by hand.
// lane 'main' watches the cable instead. withProbe adds internet tests, whose
// answer is world.online (true, false, or null for a test that couldn't run).
function setup({ lane: which = 'second', withProbe = false } = {}) {
  const world = {
    now: 1_000_000,
    alias: which === 'second' ? 'Wi-Fi' : 'Ethernet',
    addresses: [which === 'second' ? WIFI : CABLE],
    routes: ROUTES,
    routeError: null,
    online: true,
    probes: [],
    otherUp: true,
  };
  const engine = {
    status: 'on',
    startedWith: { mainAlias: 'Ethernet', secondAlias: 'Wi-Fi' },
    releaseLanes: [],
    points: [],
    releases: 0,
    pointFailures: 0,
    releaseResult: { found: 2, closed: 2, failed: 0 },
    releaseError: null,
    async pointLaneAt(selector, target) {
      if (engine.pointFailures > 0) {
        engine.pointFailures -= 1;
        throw new Error('Engine answered 500');
      }
      engine.selectors.push(selector);
      engine.points.push(target);
    },
    selectors: [],
    async releaseFallbackConnections({ lane } = {}) {
      engine.releases += 1;
      engine.releaseLanes.push(lane);
      if (engine.releaseError) throw engine.releaseError;
      return engine.releaseResult;
    },
  };
  const logs = [];
  const lane = new LaneSwitch({
    engine,
    lane: which,
    getAlias: () => world.alias,
    otherIsUp: () => world.otherUp,
    usableAddresses: () => world.addresses,
    readDefaultRoutes: async () => {
      if (world.routeError) throw world.routeError;
      return world.routes;
    },
    probe: withProbe
      ? async (outbound) => {
          world.probes.push(outbound);
          return world.online;
        }
      : null,
    log: (line) => logs.push(line),
    now: () => world.now,
  });
  // One tick of the server's loop: look, wait for background work, steer.
  async function second(ms = 1000) {
    world.now += ms;
    lane.sample();
    await lane.routeReading;
    await lane.probing;
    await lane.tick();
    await lane.releasing;
  }
  async function seconds(count, ms = 1000) {
    for (let i = 0; i < count; i += 1) await second(ms);
  }
  return { world, engine, logs, lane, second, seconds };
}

test('with the second connection up, the lane points at it once and nothing is closed', async () => {
  const { engine, logs, lane, seconds } = setup();
  await seconds(12);
  assert.deepEqual(engine.points, ['second']);
  assert.equal(engine.releases, 0);
  assert.equal(lane.target, 'second');
  assert.deepEqual(logs, ['second-lane apps now use second']);
});

test('a one-second glitch does not send anything to the cable', async () => {
  const { world, engine, seconds, second } = setup();
  await seconds(3);
  world.addresses = [];
  await second();
  world.addresses = [WIFI];
  await seconds(5);
  assert.deepEqual(engine.points, ['second']);
});

test('an outage falls back to the cable, and the return moves the stuck connections back once', async () => {
  const { world, engine, logs, lane, seconds, second } = setup();
  await seconds(3);
  world.addresses = [];
  await seconds(3);
  assert.deepEqual(engine.points, ['second', 'cable']);
  assert.equal(lane.target, 'cable');
  assert.ok(logs.includes('second connection is down (no address)'));

  world.addresses = [WIFI];
  await second();
  assert.deepEqual(engine.points, ['second', 'cable', 'second']);
  // The return is not enough: the stuck connections wait two seconds for the line to settle.
  assert.equal(engine.releases, 0);
  await second();
  assert.equal(engine.releases, 0);
  await second();
  assert.equal(engine.releases, 1);
  await seconds(2);
  assert.deepEqual(lane.lastRelease && { closed: lane.lastRelease.closed, failed: lane.lastRelease.failed }, { closed: 2, failed: 0 });
  assert.ok(logs.includes('second connection is back: closed 2 connections that had moved to the cable'));
  // And only once per return.
  await seconds(10);
  assert.equal(engine.releases, 1);
});

test('routing that starts while the second connection is down closes the stuck connections when it returns', async () => {
  const { world, engine, seconds } = setup();
  world.addresses = [];
  await seconds(1);
  // The very first reading counts at once, so routing starts on the cable.
  assert.deepEqual(engine.points, ['cable']);
  world.addresses = [WIFI];
  await seconds(6);
  assert.deepEqual(engine.points, ['cable', 'second']);
  // A return from the cable, so connections opened meanwhile are closed.
  assert.equal(engine.releases, 1);
});

test('routing that starts with the second connection up closes nothing', async () => {
  const { engine, seconds, lane } = setup();
  lane.reset();
  await seconds(8);
  assert.equal(engine.releases, 0);
});

test('a second outage during the wait cancels the close, which then happens after the next return', async () => {
  const { world, engine, seconds } = setup();
  await seconds(3);
  world.addresses = [];
  await seconds(3);
  world.addresses = [WIFI];
  await seconds(1);
  assert.deepEqual(engine.points.slice(-1), ['second']);
  world.addresses = [];
  await seconds(3);
  assert.deepEqual(engine.points.slice(-1), ['cable']);
  assert.equal(engine.releases, 0);
  world.addresses = [WIFI];
  await seconds(6);
  assert.deepEqual(engine.points.slice(-1), ['second']);
  assert.equal(engine.releases, 1);
});

test('a lane change the engine refused is tried again at the next tick', async () => {
  const { engine, logs, lane, seconds } = setup();
  engine.pointFailures = 1;
  await seconds(1);
  assert.equal(lane.target, null);
  assert.deepEqual(logs, ['could not switch second lane: Engine answered 500']);
  await seconds(1);
  assert.equal(lane.target, 'second');
  assert.deepEqual(engine.points, ['second']);
});

test('when closing fails, it is logged and the lane carries on', async () => {
  const { world, engine, logs, lane, seconds } = setup();
  await seconds(3);
  world.addresses = [];
  await seconds(3);
  world.addresses = [WIFI];
  engine.releaseError = new Error('Engine answered 500');
  await seconds(6);
  assert.ok(logs.includes('could not move connections back to the second connection: Engine answered 500'));
  assert.equal(lane.lastRelease, null);
  assert.equal(lane.target, 'second');
});

test('connections that could not be closed are counted and logged', async () => {
  const { world, engine, logs, lane, seconds } = setup();
  engine.releaseResult = { found: 3, closed: 2, failed: 1 };
  await seconds(3);
  world.addresses = [];
  await seconds(3);
  world.addresses = [WIFI];
  await seconds(6);
  assert.deepEqual(lane.lastRelease && { closed: lane.lastRelease.closed, failed: lane.lastRelease.failed }, { closed: 2, failed: 1 });
  assert.ok(logs.some((line) => line.endsWith('closed 2 connections that had moved to the cable, 1 could not be closed')));
});

test('a return with nothing stuck says nothing and leaves no note for the window', async () => {
  const { world, engine, logs, lane, seconds } = setup();
  engine.releaseResult = { found: 0, closed: 0, failed: 0 };
  await seconds(3);
  world.addresses = [];
  await seconds(3);
  world.addresses = [WIFI];
  await seconds(6);
  assert.equal(engine.releases, 1);
  assert.equal(lane.lastRelease, null);
  assert.equal(logs.filter((line) => line.startsWith('second connection is back')).length, 0);
});

test('a route read that fails never takes the second connection down', async () => {
  const { world, engine, seconds } = setup();
  world.routeError = new Error('route.exe did not answer');
  await seconds(40);
  assert.deepEqual(engine.points, ['second']);
});

test('two route reads in a row without a default route do, and a route coming back restores it', async () => {
  const { world, engine, logs, lane, seconds } = setup();
  await seconds(3);
  world.routes = ROUTES.filter((route) => route.interfaceAddress !== WIFI);
  await seconds(14);
  assert.equal(lane.target, 'cable');
  assert.ok(logs.includes('second connection is down (no default route)'));
  world.routes = ROUTES;
  await seconds(8);
  assert.equal(lane.target, 'second');
  assert.deepEqual(engine.points, ['second', 'cable', 'second']);
});

test('nothing is steered while routing is off, but the window still learns whether the line is up', async () => {
  const { world, engine, lane, seconds } = setup();
  engine.status = 'off';
  await seconds(4);
  assert.deepEqual(engine.points, []);
  assert.equal(lane.isUp(), true);
  world.addresses = [];
  await seconds(3);
  assert.equal(lane.isUp(), false);
});

test('starting routing again forgets where the lane was', async () => {
  const { engine, lane, seconds } = setup();
  await seconds(3);
  assert.equal(lane.target, 'second');
  lane.reset();
  assert.equal(lane.target, null);
  await seconds(1);
  assert.deepEqual(engine.points, ['second', 'second']);
});

test('choosing another second connection starts its health from scratch', async () => {
  const { world, lane, seconds } = setup();
  await seconds(3);
  assert.equal(lane.isUp(), true);
  world.alias = 'Phone';
  world.addresses = [];
  // A new connection's first reading counts at once, even between polls.
  assert.equal(lane.isUp(), false);
});

test('a close asked for while another is running runs once more right after it', async () => {
  const { engine, lane } = setup();
  lane.target = 'second';
  lane.startRelease();
  lane.startRelease();
  await lane.releasing;
  assert.equal(engine.releases, 2);
});

test('a close does nothing if the lane is no longer on the second connection', async () => {
  const { engine, lane } = setup();
  lane.target = 'cable';
  lane.startRelease();
  await lane.releasing;
  assert.equal(engine.releases, 0);
});

test('an answer that was lost does not leave the lane on the cable once the line is back', async () => {
  const { world, engine, lane, seconds } = setup();
  await seconds(3);
  assert.equal(lane.target, 'second');
  // The engine switches to the cable, but its answer never arrives.
  const normal = engine.pointLaneAt;
  engine.pointLaneAt = async (selector, target) => {
    engine.points.push(target);
    throw new Error('Engine did not answer');
  };
  world.addresses = [];
  await seconds(2);
  assert.deepEqual(engine.points, ['second', 'cable']);
  assert.equal(lane.target, null);
  // The line is back before the next try.
  engine.pointLaneAt = normal;
  world.addresses = [WIFI];
  await seconds(1);
  assert.deepEqual(engine.points, ['second', 'cable', 'second']);
  assert.equal(lane.target, 'second');
  // Connections may have gone to the cable meanwhile, so they are closed too.
  await seconds(4);
  assert.equal(engine.releases, 1);
});

test('the same failure is not written to the log every second', async () => {
  const { engine, logs, seconds } = setup();
  engine.pointFailures = 20;
  await seconds(10);
  assert.equal(logs.filter((line) => line.startsWith('could not switch second lane')).length, 1);
});

test('an answer from before routing restarted is ignored', async () => {
  const { engine, logs, lane, second } = setup();
  let answer;
  engine.pointLaneAt = () => new Promise((resolve) => (answer = resolve));
  const first = (async () => {
    lane.sample();
    await lane.tick();
  })();
  await new Promise((resolve) => setImmediate(resolve));
  lane.reset();
  answer();
  await first;
  assert.equal(lane.target, null);
  assert.deepEqual(logs, []);
  // The next tick sets it for real.
  engine.pointLaneAt = async (selector, target) => engine.points.push(target);
  await second();
  assert.equal(lane.target, 'second');
});

test('a route reading that arrives after another connection was chosen is ignored', async () => {
  const { world, lane } = setup();
  let finish;
  const reading = new Promise((resolve) => (finish = resolve));
  lane.readDefaultRoutes = () => reading;
  lane.sample();
  world.alias = 'Phone';
  lane.sample();
  finish([]);
  await lane.routeReading;
  assert.equal(lane.health.route, null);
});

test('an address reader that throws changes nothing and does not stop the polls', async () => {
  const { engine, logs, lane, seconds } = setup();
  await seconds(3);
  lane.usableAddresses = () => {
    throw new Error('Windows could not list the adapters');
  };
  await seconds(6);
  assert.deepEqual(engine.points, ['second']);
  assert.equal(lane.isUp(), true);
  assert.equal(logs.filter((line) => line.startsWith('could not read the network addresses')).length, 1);
});

test('closing waits while the line has just missed a poll', async () => {
  const { world, engine, seconds, second } = setup();
  await seconds(3);
  world.addresses = [];
  await seconds(3);
  world.addresses = [WIFI];
  await second();
  await second();
  // The two seconds of settling are over, but this poll has no address: not yet.
  world.addresses = [];
  await second();
  assert.equal(engine.releases, 0);
  world.addresses = [WIFI];
  await seconds(2);
  assert.equal(engine.releases, 1);
});

test('closing stops when the line drops during it, and the rest is closed a few seconds later', async () => {
  const { world, engine, lane, seconds } = setup();
  await seconds(3);
  world.addresses = [];
  await seconds(3);
  world.addresses = [WIFI];
  let calls = 0;
  engine.releaseFallbackConnections = async ({ shouldContinue }) => {
    calls += 1;
    engine.releases += 1;
    if (calls === 1) {
      // One connection is closed, then the line misses a poll.
      world.addresses = [];
      world.now += 1000;
      lane.sample();
      return { found: 3, closed: 1, failed: 0, interrupted: !shouldContinue() };
    }
    return { found: 2, closed: 2, failed: 0, interrupted: false };
  };
  await seconds(4);
  assert.equal(calls, 1);
  world.addresses = [WIFI];
  await seconds(8);
  assert.equal(calls, 2);
  assert.equal(lane.awaySince, false);
});

test('connections left behind are tried again, and the counts add up', async () => {
  const { world, engine, logs, lane, seconds } = setup();
  await seconds(3);
  world.addresses = [];
  await seconds(3);
  world.addresses = [WIFI];
  const answers = [
    { found: 3, closed: 2, failed: 1, interrupted: false },
    { found: 1, closed: 1, failed: 0, interrupted: false },
  ];
  engine.releaseFallbackConnections = async () => {
    engine.releases += 1;
    return answers.shift() ?? { found: 0, closed: 0, failed: 0, interrupted: false };
  };
  await seconds(5);
  assert.equal(engine.releases, 1);
  assert.deepEqual({ closed: lane.lastRelease.closed, failed: lane.lastRelease.failed }, { closed: 2, failed: 1 });
  await seconds(6);
  assert.equal(engine.releases, 2);
  assert.deepEqual({ closed: lane.lastRelease.closed, failed: lane.lastRelease.failed }, { closed: 3, failed: 0 });
  assert.equal(lane.awaySince, false);
  await seconds(12);
  assert.equal(engine.releases, 2);
  assert.ok(logs.includes('second connection is back: closed 1 connection that had moved to the cable'));
});

test('it gives up after three tries, and says so', async () => {
  const { world, engine, logs, seconds } = setup();
  await seconds(3);
  world.addresses = [];
  await seconds(3);
  world.addresses = [WIFI];
  engine.releaseFallbackConnections = async () => {
    engine.releases += 1;
    throw new Error('Engine answered 500');
  };
  await seconds(30);
  assert.equal(engine.releases, 3);
  assert.ok(logs.includes('gave up moving the rest of the connections back to the second connection'));
});

test('with the address back but no default route yet, nothing is closed, and a second reading takes it back to the cable', async () => {
  const { world, engine, logs, lane, seconds } = setup();
  await seconds(3);
  world.addresses = [];
  await seconds(3);
  world.routes = [];
  world.addresses = [WIFI];
  await seconds(4);
  assert.equal(engine.releases, 0);
  await seconds(8);
  assert.equal(engine.releases, 0);
  assert.equal(lane.target, 'cable');
  assert.ok(logs.includes('second connection is down (no default route)'));
  // The route comes: back to the second connection, and then the stuck ones are closed.
  world.routes = ROUTES;
  await seconds(8);
  assert.equal(lane.target, 'second');
  assert.equal(engine.releases, 1);
});

test('closing waits for a route reading taken since the line came back, and goes on without one after ten seconds', async () => {
  const { world, engine, lane, seconds } = setup();
  await seconds(3);
  world.addresses = [];
  await seconds(3);
  world.routeError = new Error('route.exe did not answer');
  world.addresses = [WIFI];
  await seconds(8);
  assert.equal(lane.target, 'second');
  assert.equal(engine.releases, 0);
  await seconds(6);
  assert.equal(engine.releases, 1);
});

test('a request made after routing restarted is not lost to a close that is still waiting from before', async () => {
  const world = { now: 5_000_000, addresses: [WIFI] };
  let releases = 0;
  const engine = {
    status: 'on',
    startedWith: { secondAlias: 'Wi-Fi' },
    async pointLaneAt() {},
    async releaseFallbackConnections() {
      releases += 1;
      return { found: 1, closed: 1, failed: 0, interrupted: false };
    },
  };
  let unblock;
  const gate = new Promise((resolve) => (unblock = resolve));
  let first = true;
  const lane = new LaneSwitch({
    engine,
    getAlias: () => 'Wi-Fi',
    usableAddresses: () => world.addresses,
    readDefaultRoutes: async () => ROUTES,
    // The first close waits behind something else, for example a Reconnect.
    runExclusive: async (task) => {
      if (first) {
        first = false;
        await gate;
      }
      return task();
    },
    log: () => {},
    now: () => world.now,
  });
  const second = async () => {
    world.now += 1000;
    lane.sample();
    await lane.routeReading;
    await lane.tick();
  };
  const outageAndReturn = async () => {
    world.addresses = [];
    for (let i = 0; i < 3; i += 1) await second();
    world.addresses = [WIFI];
    for (let i = 0; i < 5; i += 1) await second();
  };
  for (let i = 0; i < 3; i += 1) await second();
  await outageAndReturn();
  // The first close is now waiting. Routing restarts, and the line drops and returns again.
  lane.reset();
  await outageAndReturn();
  unblock();
  await lane.releasing;
  for (let i = 0; i < 10; i += 1) await second();
  await lane.releasing;
  assert.equal(releases, 1);
  assert.equal(lane.awaySince, false);
});

test('the same cycle works when nothing waits for the background work, as in the running program', async () => {
  const { world, engine, lane } = setup();
  const quickly = async () => {
    world.now += 1000;
    lane.sample();
    await lane.tick();
    // Let the background route read and close finish on their own.
    for (let i = 0; i < 20; i += 1) await Promise.resolve();
  };
  for (let i = 0; i < 4; i += 1) await quickly();
  world.addresses = [];
  for (let i = 0; i < 3; i += 1) await quickly();
  world.addresses = [WIFI];
  for (let i = 0; i < 8; i += 1) await quickly();
  assert.deepEqual(engine.points, ['second', 'cable', 'second']);
  assert.equal(engine.releases, 1);
});

test('a line that keeps its address but reaches nothing falls back after three failed tests, and returns after two passes', async () => {
  const { world, engine, logs, lane, seconds } = setup({ withProbe: true });
  await seconds(3);
  assert.deepEqual(engine.points, ['second']);
  assert.deepEqual(world.probes, ['second']);
  // The phone's mobile data is turned off: address and route stay.
  world.online = false;
  await seconds(45);
  assert.equal(lane.target, 'cable');
  assert.ok(logs.includes('second connection is down (no internet)'));
  // One pass is not enough to trust it again.
  world.online = true;
  await seconds(6);
  assert.equal(lane.target, 'cable');
  await seconds(31);
  assert.equal(lane.target, 'second');
  await seconds(4);
  assert.deepEqual(engine.points, ['second', 'cable', 'second']);
  assert.equal(engine.releases, 1);
});

test('a line with no internet stays down across a routing restart, until its tests pass again', async () => {
  const { world, engine, lane, seconds } = setup({ withProbe: true });
  await seconds(3);
  world.online = false;
  await seconds(45);
  assert.equal(lane.target, 'cable');
  // Routing restarts; the line is the same and still reaches nothing.
  lane.reset({ sameLine: true });
  await seconds(3);
  assert.deepEqual(engine.points.slice(-1), ['cable']);
  // Back: tested every five seconds while down, so two passes take seconds, not a minute.
  world.online = true;
  await seconds(12);
  assert.equal(lane.target, 'second');
});

test('a passing internet test keeps its round trip for the window, and a failing one clears it', async () => {
  const { world, lane, seconds } = setup({ withProbe: true });
  world.online = 42.4;
  await seconds(2);
  assert.equal(lane.delay, 42);
  world.online = false;
  await seconds(31);
  assert.equal(lane.delay, null);
  lane.reset({ sameLine: true });
  assert.equal(lane.delay, null);
});

test('an internet test that could not be run never takes the line down', async () => {
  const { world, engine, seconds } = setup({ withProbe: true });
  world.online = null;
  await seconds(120);
  assert.deepEqual(engine.points, ['second']);
  assert.ok(world.probes.length >= 4);
});

test('one failed internet test is not a drop, but keeps the stuck connections waiting', async () => {
  const { world, engine, lane, seconds } = setup({ withProbe: true });
  await seconds(3);
  world.addresses = [];
  await seconds(3);
  world.addresses = [WIFI];
  world.online = false;
  await seconds(4);
  // Back on the line by its address and route, but its first test failed: nothing is closed yet.
  assert.equal(lane.target, 'second');
  assert.equal(engine.releases, 0);
  world.online = true;
  await seconds(8);
  assert.equal(engine.releases, 1);
});

test('when the cable drops, its apps use the second connection, and come back when it returns', async () => {
  const { world, engine, logs, lane, seconds } = setup({ lane: 'main' });
  await seconds(3);
  assert.deepEqual(engine.points, ['cable']);
  assert.deepEqual(engine.selectors, ['main-lane']);
  world.addresses = [];
  await seconds(3);
  assert.deepEqual(engine.points, ['cable', 'second']);
  assert.equal(lane.target, 'second');
  assert.ok(logs.includes('cable is down (no address)'));
  assert.ok(logs.includes('cable apps now use second'));
  world.addresses = [CABLE];
  await seconds(6);
  assert.deepEqual(engine.points, ['cable', 'second', 'cable']);
  assert.deepEqual(engine.releaseLanes, ['main']);
  assert.ok(logs.includes('cable is back: closed 2 connections that had moved to the second connection'));
});

test('with both lines down, the cable’s apps stay on the cable', async () => {
  const { world, engine, seconds } = setup({ lane: 'main' });
  await seconds(3);
  world.otherUp = false;
  world.addresses = [];
  await seconds(6);
  assert.deepEqual(engine.points, ['cable']);
});
