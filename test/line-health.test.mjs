import assert from 'node:assert/strict';
import { test } from 'node:test';
import { LineHealth, MIN_POLL_GAP_MS, PASS_WAIT_MS, ROUTE_STALE_MS } from '../lib/line-health.mjs';

// A clock that moves one second per poll, like the server's poll loop.
function clock(start = 1_000_000) {
  let now = start;
  return {
    tick: (ms = 1000) => (now += ms),
    get now() {
      return now;
    },
  };
}

test('the first poll decides at once, in either direction', () => {
  const up = new LineHealth();
  assert.equal(up.check(true, 0), true);
  const down = new LineHealth();
  assert.equal(down.check(false, 0), false);
  assert.equal(down.reason, 'no address');
});

test('one poll without an address is a glitch, two in a row are an outage', () => {
  const health = new LineHealth();
  const time = clock();
  assert.equal(health.check(true, time.now), true);
  assert.equal(health.check(false, time.tick()), true);
  assert.equal(health.check(true, time.tick()), true);
  // The miss counter starts over after a good poll.
  assert.equal(health.check(false, time.tick()), true);
  assert.equal(health.check(false, time.tick()), false);
  assert.equal(health.reason, 'no address');
});

test('the line is back at the first good poll', () => {
  const health = new LineHealth();
  const time = clock();
  health.check(true, time.now);
  health.check(false, time.tick());
  assert.equal(health.check(false, time.tick()), false);
  assert.equal(health.check(true, time.tick()), true);
  assert.equal(health.reason, null);
});

test('a route read that failed says nothing, so it never takes the line down', () => {
  const health = new LineHealth();
  const time = clock();
  health.check(true, time.now);
  for (let i = 0; i < 10; i += 1) {
    health.noteRoute(null, time.tick(5000));
    assert.equal(health.check(true, time.now), true);
  }
});

test('two route reads in a row that worked and found no default route take the line down', () => {
  const health = new LineHealth();
  const time = clock();
  health.check(true, time.now);
  health.noteRoute(false, time.tick());
  assert.equal(health.check(true, time.tick()), true);
  health.noteRoute(false, time.tick(5000));
  assert.equal(health.check(true, time.tick()), false);
  assert.equal(health.reason, 'no default route');
  // A route showing up again brings it back at the next poll.
  health.noteRoute(true, time.tick(5000));
  assert.equal(health.check(true, time.tick()), true);
});

test('a failed read between two misses does not reset them, a good read does', () => {
  const health = new LineHealth();
  const time = clock();
  health.check(true, time.now);
  health.noteRoute(false, time.tick());
  health.noteRoute(null, time.tick());
  health.noteRoute(false, time.tick());
  assert.equal(health.check(true, time.tick()), false);

  const other = new LineHealth();
  const t = clock();
  other.check(true, t.now);
  other.noteRoute(false, t.tick());
  other.noteRoute(true, t.tick());
  other.noteRoute(false, t.tick());
  assert.equal(other.check(true, t.tick()), true);
});

test('a route reading that is too old is ignored', () => {
  const health = new LineHealth();
  const time = clock();
  health.check(true, time.now);
  health.noteRoute(false, time.now);
  health.noteRoute(false, time.tick());
  // No new reading for longer than the stale limit: the old verdict no longer counts.
  assert.equal(health.check(true, time.tick(ROUTE_STALE_MS + 1000)), true);
});

test('a route reading from the outage does not keep the line down once the address is back', () => {
  const health = new LineHealth();
  const time = clock();
  health.check(true, time.now);
  health.check(false, time.tick());
  health.noteRoute(false, time.tick());
  assert.equal(health.check(false, time.tick()), false);
  // The address is back, the last route reading still says "none": it is from before.
  assert.equal(health.check(true, time.tick()), true);
});

test('a line with an address but no default route stays down, and does not flap', () => {
  const health = new LineHealth();
  const time = clock();
  health.check(true, time.now);
  health.noteRoute(false, time.tick());
  health.noteRoute(false, time.tick());
  assert.equal(health.check(true, time.tick()), false);
  for (let i = 0; i < 6; i += 1) {
    health.noteRoute(false, time.tick(5000));
    assert.equal(health.check(true, time.tick()), false);
  }
});

test('two polls closer than the minimum gap count once', () => {
  const health = new LineHealth();
  const time = clock();
  health.check(true, time.now);
  assert.equal(health.check(false, time.tick()), true);
  // Another caller asks again at once: still the same poll.
  assert.equal(health.check(false, time.now + MIN_POLL_GAP_MS - 1), true);
  assert.equal(health.check(false, time.tick()), false);
});

test('reset forgets everything, so the next poll decides at once', () => {
  const health = new LineHealth();
  const time = clock();
  health.check(true, time.now);
  health.reset();
  assert.equal(health.up, null);
  assert.equal(health.check(false, time.tick()), false);
});

test('a miss that is old by the time the next one arrives does not add up with it', () => {
  const health = new LineHealth();
  const time = clock();
  health.check(true, time.now);
  health.noteRoute(false, time.now);
  // Nothing learned for longer than the stale limit, then another miss.
  health.noteRoute(false, time.tick(ROUTE_STALE_MS + 1000));
  assert.equal(health.check(true, time.tick()), true);
  // A second miss that follows the new one does count.
  health.noteRoute(false, time.tick(5000));
  assert.equal(health.check(true, time.tick()), false);
});

test('route misses from before an address outage do not add up with one new miss afterwards', () => {
  const health = new LineHealth();
  const time = clock();
  health.check(true, time.now);
  health.noteRoute(false, time.tick());
  health.noteRoute(false, time.tick());
  health.check(false, time.tick());
  health.check(false, time.tick());
  assert.equal(health.up, false);
  // The address returns a minute later; the first new reading alone is not a drop.
  assert.equal(health.check(true, time.tick(60_000)), true);
  health.noteRoute(false, time.tick());
  assert.equal(health.check(true, time.tick()), true);
  // A second one in a row is.
  health.noteRoute(false, time.tick(5000));
  assert.equal(health.check(true, time.tick()), false);
});

// A line that was down for lack of an address, polled once more with it back.
function returning({ tested }) {
  const health = new LineHealth();
  const time = clock();
  health.check(true, time.now, { tested });
  health.check(false, time.tick(), { tested });
  health.check(false, time.tick(), { tested });
  assert.equal(health.up, false);
  const back = time.tick();
  const up = health.check(true, back, { tested });
  return { health, time, back, up };
}

test('while lines are tested, a line whose address returns stays down until a test passes', () => {
  const { health, time, back, up } = returning({ tested: true });
  assert.equal(up, false);
  assert.equal(health.reason, 'checking');
  assert.equal(health.inDoubt(), true);
  assert.equal(health.check(true, time.tick(), { tested: true }), false);
  health.noteProbe(true, back + 500);
  assert.equal(health.check(true, time.tick(), { tested: true }), true);
  assert.equal(health.reason, null);
  assert.equal(health.inDoubt(), false);
});

test('without tests, a line is back at the first poll with an address', () => {
  const { health, up } = returning({ tested: false });
  assert.equal(up, true);
  assert.equal(health.reason, null);
});

test('a returning line whose tests fail stays down, and three failures make it offline', () => {
  const { health, time, back } = returning({ tested: true });
  for (let i = 1; i <= 3; i += 1) health.noteProbe(false, back + i * 5000);
  assert.equal(health.offline, true);
  // Long after the wait for a first pass, failures still keep it down.
  assert.equal(health.check(true, time.tick(PASS_WAIT_MS * 2), { tested: true }), false);
  assert.equal(health.reason, 'no internet');
});

test('a returning line is trusted on its address once no test could say anything for a while', () => {
  const { health, back } = returning({ tested: true });
  // Every test came back "couldn't be run".
  health.noteProbe(null, back + 5000);
  assert.equal(health.check(true, back + PASS_WAIT_MS - 1000, { tested: true }), false);
  assert.equal(health.check(true, back + PASS_WAIT_MS, { tested: true }), true);
});

test('one failed test, then tests that can’t run, doesn’t leave a returning line checking forever', () => {
  const { health, back } = returning({ tested: true });
  health.noteProbe(false, back + 5000);
  assert.equal(health.check(true, back + 5000 + PASS_WAIT_MS - 1000, { tested: true }), false);
  assert.equal(health.reason, 'checking');
  // Thirty seconds after the last test that answered, it goes on without one.
  assert.equal(health.check(true, back + 5000 + PASS_WAIT_MS, { tested: true }), true);
});

test('a routing restart keeps a returning line waiting for its first passing test', () => {
  const { health, time, back } = returning({ tested: true });
  health.restartKeeping({ offline: health.offline, awaitingPass: health.awaitingPass }, back + 1000);
  assert.equal(health.check(true, time.tick(2000), { tested: true }), false);
  assert.equal(health.reason, 'checking');
  health.noteProbe(true, time.tick());
  assert.equal(health.check(true, time.tick(), { tested: true }), true);
});

test('a single poll without an address is a glitch and asks for no test afterwards', () => {
  const health = new LineHealth();
  const time = clock();
  health.check(true, time.now, { tested: true });
  health.check(false, time.tick(), { tested: true });
  assert.equal(health.check(true, time.tick(), { tested: true }), true);
  assert.equal(health.awaitingPass, false);
});

test('the first poll after a reset never waits for a test', () => {
  const health = new LineHealth();
  assert.equal(health.check(true, 0, { tested: true }), true);
});

test('a route read that started before the address came back is ignored, whenever it ends', () => {
  const health = new LineHealth();
  const time = clock();
  health.check(true, time.now);
  health.check(false, time.tick());
  health.check(false, time.tick());
  const startedDuringOutage = time.now;
  health.check(true, time.tick());
  health.noteRoute(false, startedDuringOutage);
  assert.equal(health.route, null);
  assert.equal(health.routeMisses, 0);
});
