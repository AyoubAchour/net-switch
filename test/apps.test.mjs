import assert from 'node:assert/strict';
import { test } from 'node:test';
import {
  appKey,
  AppTracker,
  connectionLine,
  laneSelector,
  lineOutbound,
  mergeRows,
  OutsideTracker,
  parseOutsideId,
} from '../lib/apps.mjs';

const LM = 'C:\\Users\\Admin\\AppData\\Local\\Programs\\LM Studio\\LM Studio.exe';
const CHROME = 'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe';
// Line ids: the main line (a cable) and a Wi-Fi stick.
const CABLE = 'a1';
const STICK = 'b2';

function connection(id, path, { download = 0, upload = 0, chains = [`line-${CABLE}`], start = '2026-10-07T00:00:00Z' } = {}) {
  return { id, metadata: { processPath: path }, download, upload, chains, start };
}

test('each line has its own outbound and selector tags', () => {
  assert.equal(lineOutbound(STICK), 'line-b2');
  assert.equal(laneSelector(STICK), 'lane-b2');
});

test('the outbound that carries a connection decides its line, even behind another line’s selector', () => {
  assert.equal(connectionLine({ chains: ['line-b2', 'lane-b2'] }), STICK);
  // The stick's apps going through the cable while the stick is down.
  assert.equal(connectionLine({ chains: ['line-a1', 'lane-b2'] }), CABLE);
  assert.equal(connectionLine({ chains: ['line-a1'] }), CABLE);
  assert.equal(connectionLine({ chains: ['direct'] }), null);
  assert.equal(connectionLine({ chains: [] }), null);
  assert.equal(connectionLine(null), null);
});

test('speeds come from byte growth between polls, split by line', () => {
  const tracker = new AppTracker();
  const t0 = Date.parse('2026-10-07T00:01:00Z');
  // Connections that already existed before the first poll do not count as a burst.
  tracker.ingest([connection('a', LM, { download: 5_000_000 }), connection('b', CHROME, { download: 1000 })], t0);
  tracker.ingest(
    [
      connection('a', LM, { download: 6_000_000 }),
      connection('c', LM, {
        download: 500_000,
        chains: ['line-b2', 'lane-b2'],
        start: new Date(t0 + 500).toISOString(),
      }),
      connection('b', CHROME, { download: 1000 }),
    ],
    t0 + 1000,
  );

  const [lm, chrome] = tracker.snapshot({ [LM]: STICK });
  assert.equal(lm.key, appKey(LM));
  assert.equal(lm.line, STICK);
  assert.deepEqual(lm.connections, { [CABLE]: 1, [STICK]: 1 });
  // One poll of smoothing (weight 0.6) from zero.
  assert.equal(Math.round(lm.lineDown[CABLE]), 600_000);
  assert.equal(Math.round(lm.lineDown[STICK]), 300_000);
  assert.equal(Math.round(lm.rate.down), 900_000);
  assert.equal(chrome.line, null);
  assert.equal(chrome.rate.down, 0);
  // Each line's routed speed, for the busy-line rule.
  assert.equal(tracker.lineRate(CABLE).down, 1_000_000);
  assert.equal(tracker.lineRate(STICK).down, 500_000);
  assert.deepEqual(tracker.lineRate('zz'), { down: 0, up: 0 });
});

test('pinned apps stay listed even when they are not running, in any letter case', () => {
  const tracker = new AppTracker();
  const t0 = Date.parse('2026-10-07T00:01:00Z');
  tracker.ingest([connection('a', CHROME)], t0);
  const rows = tracker.snapshot({ [LM]: STICK, [CHROME.toUpperCase()]: CABLE });
  const byKey = new Map(rows.map((row) => [row.key, row]));
  assert.equal(rows.length, 2);
  assert.equal(byKey.get(appKey(LM)).line, STICK);
  assert.deepEqual(byKey.get(appKey(LM)).connections, {});
  assert.equal(byKey.get(appKey(CHROME)).line, CABLE);
});

test('a download that started before routing is measured, merged into its app row and counted on its line', () => {
  const outside = new OutsideTracker();
  const t0 = Date.parse('2026-10-07T01:10:00Z');
  const sample = (down, beforeRouting = true) => ({
    id: '192.168.1.11:50799>172.67.69.92:443',
    path: LM,
    line: CABLE,
    down,
    up: 1000,
    beforeRouting,
  });
  outside.ingest([sample(10_000_000)], t0);
  outside.ingest([sample(10_750_000)], t0 + 1000);

  const routed = new AppTracker();
  const rows = mergeRows(routed.snapshot(), outside, { [LM]: CABLE });
  assert.equal(rows.length, 1);
  const [lm] = rows;
  assert.equal(lm.key, appKey(LM));
  assert.equal(lm.line, CABLE);
  assert.equal(Math.round(lm.rate.down), 450_000); // 750 KB/s after one smoothing step (0.6)
  assert.equal(Math.round(lm.lineDown[CABLE]), 450_000);
  assert.deepEqual(
    { connections: lm.outside.connections, beforeRouting: lm.outside.beforeRouting, measured: lm.outside.measured },
    { connections: 1, beforeRouting: true, measured: true },
  );
  assert.deepEqual(lm.outside.byLine, { [CABLE]: 1 });
  // Reconnecting toward the stick would close it; toward the cable there is nothing to close.
  assert.deepEqual(outside.idsOffLine(appKey(LM), STICK), ['192.168.1.11:50799>172.67.69.92:443']);
  assert.deepEqual(outside.idsOffLine(appKey(LM), CABLE), []);
});

test('outside connections Windows cannot measure are still counted, and vanish when they close', () => {
  const outside = new OutsideTracker();
  const t0 = Date.parse('2026-10-07T01:10:00Z');
  outside.ingest([{ id: 'a', path: CHROME, line: CABLE, down: null, up: null, beforeRouting: false }], t0);
  const chrome = outside.get(appKey(CHROME));
  assert.equal(chrome.connections, 1);
  assert.equal(chrome.measured, false);
  assert.equal(chrome.beforeRouting, false);
  outside.ingest([], t0 + 1000);
  assert.equal(outside.get(appKey(CHROME)), null);
});

test('reconnect finds the right connections: engine ids per line, and outside connections by tuple and owner', () => {
  const tracker = new AppTracker();
  const t0 = Date.parse('2026-10-07T01:10:00Z');
  const third = 'c3';
  tracker.ingest(
    [
      connection('old', LM, { chains: ['line-a1', 'lane-b2'] }),
      connection('new', LM, { chains: ['line-b2', 'lane-b2'] }),
      connection('phone', LM, { chains: [`line-${third}`, 'lane-b2'] }),
    ],
    t0,
  );
  assert.deepEqual(tracker.connectionIdsFor(appKey(LM), CABLE), ['old']);
  assert.deepEqual(tracker.connectionIdsFor(appKey(LM), STICK), ['new']);
  assert.deepEqual(tracker.connectionIdsFor(appKey(CHROME), CABLE), []);
  // Everything not on the stick, on any other line.
  assert.deepEqual(tracker.connectionIdsOffLine(appKey(LM), STICK).sort(), ['old', 'phone']);

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

test('while combining, reconnect can take every outside connection of an app, on any line', () => {
  const outside = new OutsideTracker();
  const sample = (id, line) => ({ id, path: LM, line, down: 0, up: 0, beforeRouting: true });
  outside.ingest([sample('192.168.1.11:1>9.9.9.9:443', CABLE), sample('192.168.1.21:2>9.9.9.9:443', STICK)], 0);
  assert.deepEqual(outside.idsOffLine(appKey(LM), CABLE), ['192.168.1.21:2>9.9.9.9:443']);
  assert.deepEqual(outside.idsOf(appKey(LM)), ['192.168.1.11:1>9.9.9.9:443', '192.168.1.21:2>9.9.9.9:443']);
  assert.deepEqual(outside.idsOf(appKey(CHROME)), []);
});

test('idle apps disappear after the keep window; connections without a path become one unknown app', () => {
  const tracker = new AppTracker({ idleKeepMs: 60_000 });
  const t0 = Date.parse('2026-10-07T00:01:00Z');
  tracker.ingest([connection('x', ''), connection('y', '')], t0);
  assert.equal(tracker.snapshot().length, 1);
  assert.equal(tracker.snapshot()[0].key, 'unknown');
  tracker.ingest([], t0 + 30_000);
  assert.equal(tracker.snapshot().length, 1);
  tracker.ingest([], t0 + 61_000);
  assert.equal(tracker.snapshot().length, 0);
});
