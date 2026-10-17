import assert from 'node:assert/strict';
import { test } from 'node:test';
import { LaneSwitch, PROBE_EVERY_MS, QUICK_PROBE_EVERY_MS } from '../lib/lane-switch.mjs';

const CABLE_IP = '192.168.1.11';
const WIFI_IP = '192.168.1.21';
const ROUTES = [
  { gateway: '192.168.1.1', interfaceAddress: CABLE_IP, metric: 35 },
  { gateway: '192.168.1.1', interfaceAddress: WIFI_IP, metric: 55 },
];

// Three lines in priority order: the cable is the main line.
function makeLines() {
  return [
    { id: 'a1', alias: 'Ethernet', label: 'Cable', strict: false },
    { id: 'b2', alias: 'Wi-Fi', label: 'Wi-Fi stick', strict: false },
    { id: 'c3', alias: 'Ethernet 3', label: 'Phone', strict: false },
  ];
}

// A PC with three lines, a routing engine and a clock we move by hand. The
// switch watches one line (the Wi-Fi stick unless told otherwise); the other
// lines' health is world.up. withProbe adds HTTPS tests, whose answer is
// world.online (true or a round trip, false, or null for a test that couldn't
// run); withQuick adds the quick check, whose answer is world.quick.
function setup({ watch = 'b2', withProbe = false, withQuick = false } = {}) {
  const lines = makeLines();
  const world = {
    now: 1_000_000,
    lines,
    addresses: [watch === 'a1' ? CABLE_IP : WIFI_IP],
    routes: ROUTES,
    routeError: null,
    online: true,
    quick: 20,
    probes: [],
    quicks: [],
    // Internet traffic crossing the line right now.
    carrying: false,
    up: { a1: true, b2: true, c3: true },
    exhausted: new Set(),
    changes: [],
  };
  const engine = {
    status: 'on',
    startedWith: { lines: lines.map(({ id, alias }) => ({ id, alias })) },
    points: [],
    pointFailures: 0,
    async pointLaneAt(lineId, target) {
      if (engine.pointFailures > 0) {
        engine.pointFailures -= 1;
        throw new Error('Engine answered 500');
      }
      engine.points.push([lineId, target]);
    },
  };
  const logs = [];
  const lane = new LaneSwitch({
    engine,
    lineId: watch,
    getLines: () => world.lines,
    isLineUp: (id) => world.up[id],
    exhausted: () => world.exhausted,
    usableAddresses: () => world.addresses,
    readDefaultRoutes: async () => {
      if (world.routeError) throw world.routeError;
      return world.routes;
    },
    probe: withProbe
      ? async (lineId, options) => {
          world.probes.push({ lineId, ...options });
          return world.online;
        }
      : null,
    quickProbe: withQuick
      ? async (line) => {
          world.quicks.push(line.id);
          return world.quick;
        }
      : null,
    carryingTraffic: () => world.carrying,
    onChange: (change) => world.changes.push(change),
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
  }
  async function seconds(count, ms = 1000) {
    for (let i = 0; i < count; i += 1) await second(ms);
  }
  const targets = () => engine.points.map(([, target]) => target);
  return { world, engine, logs, lane, second, seconds, targets };
}

test('with its line up, a line’s selector points at it once', async () => {
  const { engine, logs, lane, seconds } = setup();
  await seconds(12);
  assert.deepEqual(engine.points, [['b2', 'b2']]);
  assert.equal(lane.target, 'b2');
  assert.equal(lane.home, true);
  assert.deepEqual(logs, ["Wi-Fi stick's apps now use Wi-Fi stick"]);
});

test('a one-second glitch moves nothing', async () => {
  const { world, seconds, second, targets } = setup();
  await seconds(3);
  world.addresses = [];
  await second();
  world.addresses = [WIFI_IP];
  await seconds(5);
  assert.deepEqual(targets(), ['b2']);
});

test('an outage sends the line’s apps to the main line, and they come back without anything being closed', async () => {
  const { world, logs, lane, seconds, targets } = setup();
  await seconds(3);
  world.addresses = [];
  await seconds(3);
  assert.deepEqual(targets(), ['b2', 'a1']);
  assert.equal(lane.home, false);
  assert.ok(logs.includes('Wi-Fi stick is down (no address)'));
  assert.ok(logs.includes("Wi-Fi stick's apps now use Cable"));
  assert.deepEqual(world.changes, [{ up: false, reason: 'no address' }]);

  world.addresses = [WIFI_IP];
  await seconds(2);
  assert.deepEqual(targets(), ['b2', 'a1', 'b2']);
  assert.deepEqual(world.changes.at(-1), { up: true, reason: null });
  // The fake engine can't close anything: a call would have thrown.
  await seconds(10);
  assert.deepEqual(targets(), ['b2', 'a1', 'b2']);
});

test('with the main line down too, the next line in priority order takes over', async () => {
  const { world, seconds, targets } = setup();
  await seconds(3);
  world.up.a1 = false;
  world.addresses = [];
  await seconds(3);
  assert.deepEqual(targets(), ['b2', 'c3']);
  // The main line returns: it is first in line again.
  world.up.a1 = true;
  await seconds(1);
  assert.deepEqual(targets(), ['b2', 'c3', 'a1']);
});

test('a line kept to its own apps, or out of data, never takes over for another', async () => {
  const strict = setup();
  strict.world.lines[0].strict = true;
  await strict.seconds(3);
  strict.world.addresses = [];
  await strict.seconds(3);
  assert.deepEqual(strict.targets(), ['b2', 'c3']);

  const capped = setup();
  capped.world.exhausted = new Set(['a1', 'c3']);
  await capped.seconds(3);
  capped.world.addresses = [];
  await capped.seconds(3);
  // Nowhere better to go: the apps stay on their own line.
  assert.deepEqual(capped.targets(), ['b2']);
});

test('a line out of data sends its own apps elsewhere even while it is connected', async () => {
  const { world, seconds, targets } = setup();
  await seconds(3);
  world.exhausted = new Set(['b2']);
  await seconds(1);
  assert.deepEqual(targets(), ['b2', 'a1']);
  world.exhausted = new Set();
  await seconds(1);
  assert.deepEqual(targets(), ['b2', 'a1', 'b2']);
});

test('the main line’s apps move only when another line is up', async () => {
  const { world, seconds, targets } = setup({ watch: 'a1' });
  await seconds(3);
  assert.deepEqual(targets(), ['a1']);
  world.up.b2 = false;
  world.up.c3 = false;
  world.addresses = [];
  await seconds(4);
  assert.deepEqual(targets(), ['a1']);
  world.up.b2 = true;
  await seconds(1);
  assert.deepEqual(targets(), ['a1', 'b2']);
});

test('a line added since routing started, and routing with one line, steer nothing', async () => {
  const added = setup();
  added.engine.startedWith = { lines: [{ id: 'a1', alias: 'Ethernet' }, { id: 'c3', alias: 'Ethernet 3' }] };
  await added.seconds(4);
  assert.deepEqual(added.engine.points, []);

  const alone = setup({ watch: 'a1', withProbe: true });
  alone.engine.startedWith = { lines: [{ id: 'a1', alias: 'Ethernet' }] };
  await alone.seconds(40);
  assert.deepEqual(alone.engine.points, []);
  assert.deepEqual(alone.world.probes, [], 'nothing to fall back to, so nothing is tested');
});

test('a lane change the engine refused is tried again at the next tick, and logged once', async () => {
  const { engine, logs, lane, seconds } = setup();
  engine.pointFailures = 20;
  await seconds(10);
  assert.equal(lane.target, null);
  assert.equal(logs.filter((line) => line.startsWith("could not point Wi-Fi stick's apps at another line")).length, 1);
  engine.pointFailures = 0;
  await seconds(1);
  assert.equal(lane.target, 'b2');
});

test('a route read that fails never takes the line down; two reads without a default route do', async () => {
  const failing = setup();
  failing.world.routeError = new Error('route.exe did not answer');
  await failing.seconds(40);
  assert.deepEqual(failing.targets(), ['b2']);

  const { world, logs, lane, seconds, targets } = setup();
  await seconds(3);
  world.routes = ROUTES.filter((route) => route.interfaceAddress !== WIFI_IP);
  await seconds(14);
  assert.equal(lane.target, 'a1');
  assert.ok(logs.includes('Wi-Fi stick is down (no default route)'));
  world.routes = ROUTES;
  await seconds(8);
  assert.deepEqual(targets(), ['b2', 'a1', 'b2']);
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

test('starting routing again forgets where the selector was', async () => {
  const { lane, seconds, targets } = setup();
  await seconds(3);
  lane.reset();
  assert.equal(lane.target, null);
  await seconds(1);
  assert.deepEqual(targets(), ['b2', 'b2']);
});

test('a line moved to another adapter starts its health from scratch', async () => {
  const { world, lane, seconds } = setup();
  await seconds(3);
  assert.equal(lane.isUp(), true);
  world.lines[1].alias = 'Wi-Fi 2';
  world.addresses = [];
  // A new adapter's first reading counts at once, even between polls.
  assert.equal(lane.isUp(), false);
});

test('an answer that was lost does not leave the apps elsewhere once the line is back', async () => {
  const { world, engine, lane, seconds, targets } = setup();
  await seconds(3);
  // The engine switches, but its answer never arrives.
  const normal = engine.pointLaneAt;
  engine.pointLaneAt = async (lineId, target) => {
    engine.points.push([lineId, target]);
    throw new Error('Engine did not answer');
  };
  world.addresses = [];
  await seconds(2);
  assert.deepEqual(targets(), ['b2', 'a1']);
  assert.equal(lane.target, null);
  engine.pointLaneAt = normal;
  world.addresses = [WIFI_IP];
  await seconds(1);
  assert.deepEqual(targets(), ['b2', 'a1', 'b2']);
  assert.equal(lane.target, 'b2');
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
  engine.pointLaneAt = async (lineId, target) => engine.points.push([lineId, target]);
  await second();
  assert.equal(lane.target, 'b2');
});

test('a route reading that arrives after the line moved to another adapter is ignored', async () => {
  const { world, lane } = setup();
  let finish;
  const reading = new Promise((resolve) => (finish = resolve));
  lane.readDefaultRoutes = () => reading;
  lane.sample();
  world.lines[1].alias = 'Wi-Fi 2';
  lane.sample();
  finish([]);
  await lane.routeReading;
  assert.equal(lane.health.route, null);
});

test('an address reader that throws changes nothing and does not stop the polls', async () => {
  const { logs, lane, seconds, targets } = setup();
  await seconds(3);
  lane.usableAddresses = () => {
    throw new Error('Windows could not list the adapters');
  };
  await seconds(6);
  assert.deepEqual(targets(), ['b2']);
  assert.equal(lane.isUp(), true);
  assert.equal(logs.filter((line) => line.startsWith('could not read the network addresses')).length, 1);
});

test('the same cycle works when nothing waits for the background work, as in the running program', async () => {
  const { world, lane, targets } = setup();
  const quickly = async () => {
    world.now += 1000;
    lane.sample();
    await lane.tick();
    // Let the background route read finish on its own.
    for (let i = 0; i < 20; i += 1) await Promise.resolve();
  };
  for (let i = 0; i < 4; i += 1) await quickly();
  world.addresses = [];
  for (let i = 0; i < 3; i += 1) await quickly();
  world.addresses = [WIFI_IP];
  for (let i = 0; i < 8; i += 1) await quickly();
  assert.deepEqual(targets(), ['b2', 'a1', 'b2']);
});

test('a line that keeps its address but reaches nothing moves its apps after three failed tests, and gets them back after two passes', async () => {
  const { world, logs, lane, seconds, targets } = setup({ withProbe: true });
  await seconds(3);
  assert.deepEqual(targets(), ['b2']);
  assert.deepEqual(world.probes, [{ lineId: 'b2', both: false }]);
  // The phone's mobile data is turned off: address and route stay.
  world.online = false;
  await seconds(45);
  assert.equal(lane.target, 'a1');
  assert.ok(logs.includes('Wi-Fi stick is down (no internet)'));
  // One pass is not enough to trust it again.
  world.online = true;
  await seconds(6);
  assert.equal(lane.target, 'a1');
  await seconds(31);
  assert.equal(lane.target, 'b2');
  assert.deepEqual(targets(), ['b2', 'a1', 'b2']);
});

test('while lines are tested, a line whose address returns gets its apps back only after a test passes', async () => {
  const { world, lane, seconds, second, targets } = setup({ withProbe: true });
  await seconds(3);
  world.addresses = [];
  await seconds(3);
  assert.equal(lane.target, 'a1');
  // The address is back, but the phone's data isn't yet.
  world.addresses = [WIFI_IP];
  world.online = false;
  await seconds(4);
  assert.equal(lane.target, 'a1');
  assert.equal(lane.health.reason, 'checking');
  world.online = true;
  await seconds(6);
  assert.equal(lane.target, 'b2');
  assert.deepEqual(targets(), ['b2', 'a1', 'b2']);

  // A clean return is tested at once, so it takes a second or two.
  world.addresses = [];
  await seconds(3);
  world.addresses = [WIFI_IP];
  await second();
  await second();
  assert.equal(lane.target, 'b2');
});

test('a line with no internet stays down across a routing restart, until its tests pass again', async () => {
  const { world, engine, lane, seconds } = setup({ withProbe: true });
  await seconds(3);
  world.online = false;
  await seconds(45);
  assert.equal(lane.target, 'a1');
  // Routing restarts; the line is the same and still reaches nothing.
  lane.reset({ sameLine: true });
  await seconds(3);
  assert.deepEqual(engine.points.at(-1), ['b2', 'a1']);
  // Tested every five seconds while down, so two passes take seconds, not a minute.
  world.online = true;
  await seconds(12);
  assert.equal(lane.target, 'b2');
});

test('a passing test keeps its round trip for the window, and a failing one clears it', async () => {
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

test('a busy line that is too slow to answer its tests stays up while traffic crosses it', async () => {
  const { world, logs, lane, seconds, targets } = setup({ withProbe: true });
  await seconds(3);
  // A big transfer fills the line: the tests time out, but data keeps moving.
  world.online = false;
  world.carrying = true;
  await seconds(60);
  assert.deepEqual(targets(), ['b2']);
  assert.ok(logs.includes("Wi-Fi stick didn't answer an internet test in time, but it is carrying traffic, so it still counts as working"));
  // The traffic stops and the tests still fail: now it is a dead line.
  world.carrying = false;
  await seconds(45);
  assert.equal(lane.target, 'a1');
});

test('a healthy line asks one test site; after a failed test, both at once', async () => {
  const { world, seconds } = setup({ withProbe: true });
  await seconds(3);
  assert.deepEqual(world.probes.map((item) => item.both), [false]);
  world.online = false;
  // The next test, 30 s after the first, fails; the retry 5 s later asks both.
  await seconds(PROBE_EVERY_MS / 1000 + 6);
  assert.deepEqual(world.probes.map((item) => item.both), [false, false, true]);
});

test('a test that could not be run never takes the line down', async () => {
  const { world, seconds, targets } = setup({ withProbe: true });
  world.online = null;
  await seconds(120);
  assert.deepEqual(targets(), ['b2']);
  assert.ok(world.probes.length >= 4);
});

test('with the quick check, a healthy line is checked every 15 seconds and the HTTPS test only confirms a failure', async () => {
  const { world, lane, seconds, targets } = setup({ withProbe: true, withQuick: true });
  await seconds(3);
  assert.deepEqual(world.quicks, ['b2']);
  assert.deepEqual(world.probes, []);
  assert.equal(lane.delay, 20);
  await seconds(QUICK_PROBE_EVERY_MS / 1000);
  assert.deepEqual(world.quicks, ['b2', 'b2']);
  assert.deepEqual(world.probes, []);

  // A quick check that fails on a line that works: the HTTPS test says it works.
  world.quick = false;
  await seconds(QUICK_PROBE_EVERY_MS / 1000);
  assert.equal(world.probes.length, 1);
  assert.equal(lane.health.probeFails, 0);

  // Both fail: from now on only the HTTPS test counts, every five seconds, until it passes.
  world.online = false;
  await seconds(QUICK_PROBE_EVERY_MS / 1000);
  const quicksBefore = world.quicks.length;
  await seconds(12);
  assert.equal(world.quicks.length, quicksBefore);
  assert.equal(lane.target, 'a1');
  assert.ok(world.probes.slice(-2).every((item) => item.both));
  world.online = true;
  world.quick = 20;
  await seconds(12);
  assert.deepEqual(targets(), ['b2', 'a1', 'b2']);
});

test('a quick check that could not be run falls back to the HTTPS test', async () => {
  const { world, seconds } = setup({ withProbe: true, withQuick: true });
  world.quick = null;
  await seconds(2);
  assert.deepEqual(world.probes, [{ lineId: 'b2', both: false }]);
});

test('a line out of data is not tested, so it uses no more of it', async () => {
  const { world, seconds } = setup({ withProbe: true, withQuick: true });
  world.exhausted = new Set(['b2']);
  await seconds(40);
  assert.deepEqual(world.quicks, []);
  assert.deepEqual(world.probes, []);
});
