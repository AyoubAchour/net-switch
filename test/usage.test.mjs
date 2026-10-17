import assert from 'node:assert/strict';
import { test } from 'node:test';
import { BUSY_BYTES_PER_SECOND, PEAK_HALF_LIFE_MS, periodStart, Usage } from '../lib/usage.mjs';

const at = (text) => new Date(text).getTime();
const MB = 1024 * 1024;

test('a daily cap counts from local midnight; a monthly one from its reset day', () => {
  assert.equal(periodStart({ period: 'day' }, at('2026-10-17T15:30:00')), at('2026-10-17T00:00:00'));
  assert.equal(periodStart({ period: 'month' }, at('2026-10-17T15:30:00')), at('2026-10-01T00:00:00'));
  assert.equal(periodStart({ period: 'month', resetDay: 20 }, at('2026-10-17T15:30:00')), at('2026-09-20T00:00:00'));
  assert.equal(periodStart({ period: 'month', resetDay: 17 }, at('2026-10-17T15:30:00')), at('2026-10-17T00:00:00'));
  // Across a new year.
  assert.equal(periodStart({ period: 'month', resetDay: 5 }, at('2027-01-02T08:00:00')), at('2026-12-05T00:00:00'));
  // No cap: counted per calendar month.
  assert.equal(periodStart(null, at('2026-10-17T15:30:00')), at('2026-10-01T00:00:00'));
});

test('data use adds up both directions from the adapter counters, and survives a counter restart', () => {
  const usage = new Usage();
  const phone = { id: 'c3', cap: { bytes: 100 * MB, period: 'day' } };
  let counter = { rx: 1000 * MB, tx: 10 * MB };
  const now = at('2026-10-17T10:00:00');
  // The first reading only sets where counting starts.
  usage.ingest([phone], () => counter, () => null, now);
  assert.equal(usage.used('c3').bytes, 0);
  counter = { rx: 1030 * MB, tx: 15 * MB };
  usage.ingest([phone], () => counter, () => null, now + 1000);
  assert.equal(usage.used('c3').bytes, 35 * MB);
  // The phone reconnected: its counters start over from zero.
  counter = { rx: 2 * MB, tx: 1 * MB };
  usage.ingest([phone], () => counter, () => null, now + 2000);
  assert.equal(usage.used('c3').bytes, 38 * MB);
  // No reading this second: nothing is added, and nothing is lost.
  usage.ingest([phone], () => null, () => null, now + 3000);
  assert.equal(usage.used('c3').bytes, 38 * MB);
});

test('a line is out of data once its cap is reached, until the next period', () => {
  const usage = new Usage();
  const phone = { id: 'c3', cap: { bytes: 10 * MB, period: 'day' } };
  let counter = { rx: 0, tx: 0 };
  const day = at('2026-10-17T22:00:00');
  usage.ingest([phone], () => counter, () => null, day);
  counter = { rx: 11 * MB, tx: 0 };
  usage.ingest([phone], () => counter, () => null, day + 1000);
  assert.deepEqual([...usage.exhausted([phone], day + 1000)], ['c3']);
  // A higher cap makes it usable again.
  assert.deepEqual([...usage.exhausted([{ ...phone, cap: { bytes: 20 * MB, period: 'day' } }], day + 1000)], []);
  // Midnight: a new day starts from zero.
  const tomorrow = at('2026-10-18T00:00:05');
  usage.ingest([phone], () => counter, () => null, tomorrow);
  assert.equal(usage.used('c3').bytes, 0);
  assert.deepEqual([...usage.exhausted([phone], tomorrow)], []);
  // A line without a cap is never out of data.
  assert.deepEqual([...usage.exhausted([{ id: 'c3', cap: null }], day + 1000)], []);
});

test('what was used is saved and read back, and lines that are gone are forgotten', () => {
  const usage = new Usage();
  usage.lines = { c3: { bytes: 5, periodStart: 1 }, b2: { bytes: 9, periodStart: 1 } };
  usage.peaks = { c3: 2 * MB };
  const copy = new Usage().load(JSON.parse(JSON.stringify(usage.toJSON())));
  assert.deepEqual(copy.toJSON(), usage.toJSON());
  copy.keepOnly(['c3']);
  assert.deepEqual(Object.keys(copy.lines), ['c3']);
  // Damaged entries are skipped.
  assert.deepEqual(new Usage().load({ lines: { x: { bytes: 'a' } }, peaks: { y: -1 } }).toJSON(), { lines: {}, peaks: {} });
  assert.deepEqual(new Usage().load(null).toJSON(), { lines: {}, peaks: {} });
});

test('Auto combining weighs each line by its top speed while busy; idle time changes nothing', () => {
  const usage = new Usage();
  const cable = { id: 'a1', cap: null };
  const phone = { id: 'c3', cap: null };
  const t0 = at('2026-10-17T10:00:00');
  const rates = { a1: 4 * MB, c3: 1 * MB };
  usage.ingest([cable, phone], () => null, (line) => rates[line.id], t0);
  assert.deepEqual(usage.autoWeights([cable, phone]), { a1: 4 * MB, c3: 1 * MB });
  // Light use says nothing about what a line can do.
  rates.a1 = BUSY_BYTES_PER_SECOND / 2;
  usage.ingest([cable, phone], () => null, (line) => rates[line.id], t0 + 3_600_000);
  assert.equal(usage.autoWeights([cable, phone]).a1, 4 * MB);
  // A line not measured yet gets the average of the others.
  assert.deepEqual(usage.autoWeights([cable, phone, { id: 'b2' }]).b2, (4 * MB + 1 * MB) / 2);
  // Nothing measured: equal.
  assert.deepEqual(new Usage().autoWeights([cable, phone]), { a1: 1, c3: 1 });
});

test('a line that got slower is followed as it is used, fading by half per half-life of busy time', () => {
  const usage = new Usage();
  const phone = { id: 'c3', cap: null };
  let now = at('2026-10-17T10:00:00');
  usage.notePeak('c3', 8 * MB, now);
  // Busy at 1 MB/s for one half-life, read every five seconds.
  for (let elapsed = 0; elapsed < PEAK_HALF_LIFE_MS; elapsed += 5000) {
    now += 5000;
    usage.ingest([phone], () => null, () => 1 * MB, now);
  }
  const weight = usage.autoWeights([phone]).c3;
  assert.ok(Math.abs(weight - 4 * MB) < 0.01 * MB, String(weight / MB));
});
