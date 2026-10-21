import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import test from 'node:test';
import { heldSweepLatency, heldUDPSweepGate, ledgerDigest } from '../tests/windows/udp-capacity.mjs';

const token = (app, serial) => `${app.toString(16).padStart(8, '0')}${serial.toString(16).padStart(8, '0')}`;

// One app's ledger and the verify reply the capacity client would send for it.
function app(id, samplesUS, failures = {}) {
  const failed = Object.values(failures).reduce((n, count) => n + count, 0);
  const tokens = Array.from({ length: samplesUS.length + failed }, (_, i) => token(id, i + 1));
  const digest = ledgerDigest(tokens);
  return { app: id, expectedCount: tokens.length, expectedDigest: digest,
    result: { checked: tokens.length, echoed: samplesUS.length, samplesUS, failures, heldDigest: digest } };
}

test('the held-sweep gate matches the locked design numbers', () => {
  assert.deepEqual({ ...heldUDPSweepGate }, { concurrency: 32, p99US: 250_000, sweepMS: 30_000 });
});

test('the ledger digest is SHA-256 over raw 8-byte tokens in held order', () => {
  const tokens = [token(1, 1), token(1, 2)];
  const expected = createHash('sha256').update(Buffer.from(tokens.join(''), 'hex')).digest('hex');
  assert.equal(ledgerDigest(tokens), expected);
  assert.notEqual(ledgerDigest(tokens.toReversed()), expected);
  assert.equal(ledgerDigest([]), createHash('sha256').digest('hex'));
});

test('p99 is the nearest rank over every held session across apps', () => {
  // 1..100 ms split unevenly and unsorted across two apps: rank ceil(0.99 * 100) = 99.
  const values = Array.from({ length: 100 }, (_, i) => (i + 1) * 1000).reverse();
  const latency = heldSweepLatency({ held: 100, sweepMS: 1000, apps: [app(1, values.slice(0, 37)), app(2, values.slice(37))] });
  assert.equal(latency.population, 100);
  assert.equal(latency.quantilesUS.p99, 99_000);
  assert.equal(latency.quantilesUS.p50, 50_000);
  assert.equal(latency.maxUS, 100_000);
  assert.equal(latency.histogram.counts.reduce((n, count) => n + count, 0) + latency.histogram.over, 100);
  assert.deepEqual(latency.pass, { represented: true, p99: true, sweep: true });
  assert(latency.passed);
});

test('the gate boundaries are inclusive and one microsecond or millisecond over fails', () => {
  const at = heldSweepLatency({ held: 1, sweepMS: 30_000, apps: [app(1, [250_000])] });
  assert(at.passed);
  const over = heldSweepLatency({ held: 1, sweepMS: 30_000.001, apps: [app(1, [250_001])] });
  assert.deepEqual(over.pass, { represented: true, p99: false, sweep: false });
});

test('failed echoes are censored above every sample, never counted as zero', () => {
  const fast = Array(198).fill(1000);
  // Two failures in 200 sessions: rank 198 is still an exact echo.
  const two = heldSweepLatency({ held: 200, sweepMS: 1, apps: [app(1, fast, { TIMEOUT: 2 })] });
  assert.equal(two.quantilesUS.p99, 1000);
  assert.equal(two.minUS, 1000);
  assert.equal(two.maxUS, null);
  assert.equal(two.censored, 2);
  assert.deepEqual(two.failures, { TIMEOUT: 2 });
  assert(two.pass.p99 && two.pass.represented);
  // A third failure moves rank 198 onto a censored session.
  const three = heldSweepLatency({ held: 200, sweepMS: 1, apps: [app(1, fast.slice(1), { TIMEOUT: 2, ECONNRESET: 1 })] });
  assert.equal(three.quantilesUS.p99, null);
  assert.equal(three.p99MS, null);
  assert.equal(three.pass.p99, false);
});

test('an app without a verify reply leaves its sessions censored and fails representation', () => {
  const missing = app(2, Array(50).fill(1000));
  const latency = heldSweepLatency({ held: 100, sweepMS: 1, apps: [app(1, Array(50).fill(1000)),
    { ...missing, result: undefined, error: 'UDP 2 verify deadline' }] });
  assert.equal(latency.echoed, 50);
  assert.equal(latency.censored, 50);
  assert.equal(latency.quantilesUS.p99, null);
  assert.deepEqual(latency.pass, { represented: false, p99: false, sweep: true });
  assert.equal(latency.apps[1].error, 'UDP 2 verify deadline');
});

test('a swept set that differs from the host ledger fails representation', () => {
  const drifted = app(1, Array(10).fill(1000));
  drifted.expectedDigest = ledgerDigest(Array.from({ length: 10 }, (_, i) => token(1, i + 2)));
  const latency = heldSweepLatency({ held: 10, sweepMS: 1, apps: [drifted] });
  assert.equal(latency.apps[0].digestMatches, false);
  assert.equal(latency.pass.represented, false);
  assert.equal(latency.pass.p99, false, 'A p99 over the wrong population must not pass');
});

test('ledgers that do not add up to the held count fail representation', () => {
  const latency = heldSweepLatency({ held: 11, sweepMS: 1, apps: [app(1, Array(10).fill(1000))] });
  assert.equal(latency.population, 11);
  assert.equal(latency.censored, 1);
  assert.equal(latency.pass.represented, false);
});

test('a zero or fractional sample is rejected rather than trusted', () => {
  for (const bad of [0, 1.5, -1]) {
    const latency = heldSweepLatency({ held: 2, sweepMS: 1, apps: [app(1, [1000, bad])] });
    assert.equal(latency.pass.represented, false);
    assert.equal(latency.echoed, 0);
    assert.equal(latency.minUS, null);
  }
});

test('invalid failure counts cannot disguise excess echoes as held sessions', () => {
  for (const bad of [-1, 0.5, '1', Number.MAX_SAFE_INTEGER + 1]) {
    const entry = app(1, [1, 1, 1]);
    entry.expectedCount = entry.result.checked = 2;
    entry.result.failures = { OTHER: bad };
    const result = heldSweepLatency({ held: 2, sweepMS: 1, apps: [entry] });
    assert.equal(result.passed, false);
    assert.equal(result.pass.represented, false);
    assert(result.censored >= 0);
  }
});

test('invalid sweep times and duplicated app populations cannot pass', () => {
  for (const sweepMS of [-1, NaN, Infinity, '1']) {
    assert.equal(heldSweepLatency({ held: 1, sweepMS, apps: [app(1, [1])] }).pass.sweep, false);
  }
  const duplicate = app(1, [1]);
  assert.equal(heldSweepLatency({ held: 2, sweepMS: 1, apps: [duplicate, duplicate] }).pass.represented, false);
});
