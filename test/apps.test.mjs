import assert from 'node:assert/strict';
import { test } from 'node:test';
import {
  appKey,
  AppTracker,
  connectionLane,
  isFallbackConnection,
  mergeRows,
  OutsideTracker,
  parseOutsideId,
} from '../lib/apps.mjs';

const LM = 'C:\\Users\\Admin\\AppData\\Local\\Programs\\LM Studio\\LM Studio.exe';
const CHROME = 'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe';

function connection(id, path, { download = 0, upload = 0, chains = ['cable'], start = '2026-10-07T00:00:00Z' } = {}) {
  return { id, metadata: { processPath: path }, download, upload, chains, start };
}

test('the outbound that carries a connection decides its lane, even behind the selector', () => {
  assert.equal(connectionLane({ chains: ['second', 'second-lane'] }), 'second');
  assert.equal(connectionLane({ chains: ['cable', 'second-lane'] }), 'main');
  assert.equal(connectionLane({ chains: ['cable'] }), 'main');
});

test('only a connection that the selector sent to the cable counts as stuck on the fallback', () => {
  // What the engine reports: the carrying outbound first, the selector last.
  assert.equal(isFallbackConnection({ chains: ['cable', 'second-lane'] }), true);
  assert.equal(isFallbackConnection({ chains: ['second', 'second-lane'] }), false);
  // Connections that never went through the selector belong on the cable.
  assert.equal(isFallbackConnection({ chains: ['cable'] }), false);
  assert.equal(isFallbackConnection({ chains: [] }), false);
  assert.equal(isFallbackConnection({}), false);
  assert.equal(isFallbackConnection(null), false);
});

test('while the cable is down, a connection the cable lane sent to the second connection counts as stuck there', () => {
  const stuck = (chains) => isFallbackConnection({ chains }, 'main-lane', 'second');
  assert.equal(stuck(['second', 'main-lane']), true);
  assert.equal(stuck(['cable', 'main-lane']), false);
  // The second connection's own apps are where they belong.
  assert.equal(stuck(['second', 'second-lane']), false);
});

test('speeds come from byte growth between polls, split by lane', () => {
  const tracker = new AppTracker();
  const t0 = Date.parse('2026-10-07T00:01:00Z');
  // Connections that already existed before the first poll do not count as a burst.
  tracker.ingest([connection('a', LM, { download: 5_000_000 }), connection('b', CHROME, { download: 1000 })], t0);
  tracker.ingest(
    [
      connection('a', LM, { download: 6_000_000 }),
      connection('c', LM, {
        download: 500_000,
        chains: ['second', 'second-lane'],
        start: new Date(t0 + 500).toISOString(),
      }),
      connection('b', CHROME, { download: 1000 }),
    ],
    t0 + 1000,
  );

  const [lm, chrome] = tracker.snapshot([LM]);
  assert.equal(lm.key, appKey(LM));
  assert.equal(lm.lane, 'second');
  assert.deepEqual(lm.connections, { main: 1, second: 1 });
  // One poll of smoothing (weight 0.6) from zero.
  assert.equal(Math.round(lm.laneDown.main), 600_000);
  assert.equal(Math.round(lm.laneDown.second), 300_000);
  assert.equal(chrome.lane, 'main');
  assert.equal(chrome.rate.down, 0);
});

test('apps moved to the second connection stay listed even when they are not running', () => {
  const tracker = new AppTracker();
  const rows = tracker.snapshot([LM]);
  assert.equal(rows.length, 1);
  assert.equal(rows[0].lane, 'second');
  assert.deepEqual(rows[0].connections, { main: 0, second: 0 });
});

test('a download that started before routing is measured, merged into its app row and colored by its lane', () => {
  const outside = new OutsideTracker();
  const t0 = Date.parse('2026-10-07T01:10:00Z');
  const sample = (down, beforeRouting = true) => ({
    id: '192.168.1.11:50799>172.67.69.92:443',
    path: LM,
    lane: 'main',
    down,
    up: 1000,
    beforeRouting,
  });
  outside.ingest([sample(10_000_000)], t0);
  outside.ingest([sample(10_750_000)], t0 + 1000);

  const routed = new AppTracker();
  const rows = mergeRows(routed.snapshot([]), outside, []);
  assert.equal(rows.length, 1);
  const [lm] = rows;
  assert.equal(lm.key, appKey(LM));
  assert.equal(lm.lane, 'main');
  assert.equal(Math.round(lm.rate.down), 450_000); // 750 KB/s after one smoothing step (0.6)
  assert.equal(Math.round(lm.laneDown.main), 450_000);
  assert.deepEqual(
    { connections: lm.outside.connections, beforeRouting: lm.outside.beforeRouting, measured: lm.outside.measured },
    { connections: 1, beforeRouting: true, measured: true },
  );
  assert.deepEqual(lm.outside.byLane, { main: 1, second: 0 });
  // Reconnecting toward the stick would close it; toward the cable there is nothing to close.
  assert.deepEqual(outside.idsOffLane(appKey(LM), 'second'), ['192.168.1.11:50799>172.67.69.92:443']);
  assert.deepEqual(outside.idsOffLane(appKey(LM), 'main'), []);
});

test('outside connections Windows cannot measure are still counted, and vanish when they close', () => {
  const outside = new OutsideTracker();
  const t0 = Date.parse('2026-10-07T01:10:00Z');
  outside.ingest([{ id: 'a', path: CHROME, lane: 'main', down: null, up: null, beforeRouting: false }], t0);
  const chrome = outside.get(appKey(CHROME));
  assert.equal(chrome.connections, 1);
  assert.equal(chrome.measured, false);
  assert.equal(chrome.beforeRouting, false);
  outside.ingest([], t0 + 1000);
  assert.equal(outside.get(appKey(CHROME)), null);
});

test('reconnect finds the right connections: engine ids per lane, and outside connections by tuple and owner', () => {
  const tracker = new AppTracker();
  const t0 = Date.parse('2026-10-07T01:10:00Z');
  tracker.ingest(
    [connection('old', LM, { chains: ['cable', 'second-lane'] }), connection('new', LM, { chains: ['second', 'second-lane'] })],
    t0,
  );
  assert.deepEqual(tracker.connectionIdsFor(appKey(LM), 'main'), ['old']);
  assert.deepEqual(tracker.connectionIdsFor(appKey(LM), 'second'), ['new']);
  assert.deepEqual(tracker.connectionIdsFor(appKey(CHROME), 'main'), []);

  assert.deepEqual(parseOutsideId('192.168.1.11:50799>172.67.69.92:443|13284|2026-10-06T22:40:31.0000000Z'), {
    local: '192.168.1.11',
    lport: 50799,
    remote: '172.67.69.92',
    rport: 443,
    pid: 13284,
    created: '2026-10-06T22:40:31.0000000Z',
  });
  assert.equal(parseOutsideId('[fe80::1]:1>x|1|y'), null);
});

test('while combining, reconnect can take every outside connection of an app, on either line', () => {
  const outside = new OutsideTracker();
  const sample = (id, lane) => ({ id, path: LM, lane, down: 0, up: 0, beforeRouting: true });
  outside.ingest([sample('192.168.1.11:1>9.9.9.9:443', 'main'), sample('192.168.1.21:2>9.9.9.9:443', 'second')], 0);
  assert.deepEqual(outside.idsOffLane(appKey(LM), 'main'), ['192.168.1.21:2>9.9.9.9:443']);
  assert.deepEqual(outside.idsOf(appKey(LM)), ['192.168.1.11:1>9.9.9.9:443', '192.168.1.21:2>9.9.9.9:443']);
  assert.deepEqual(outside.idsOf(appKey(CHROME)), []);
});

test('idle apps disappear after the keep window; connections without a path become one unknown app', () => {
  const tracker = new AppTracker({ idleKeepMs: 60_000 });
  const t0 = Date.parse('2026-10-07T00:01:00Z');
  tracker.ingest([connection('x', ''), connection('y', '')], t0);
  assert.equal(tracker.snapshot([]).length, 1);
  assert.equal(tracker.snapshot([])[0].key, 'unknown');
  tracker.ingest([], t0 + 30_000);
  assert.equal(tracker.snapshot([]).length, 1);
  tracker.ingest([], t0 + 61_000);
  assert.equal(tracker.snapshot([]).length, 0);
});
