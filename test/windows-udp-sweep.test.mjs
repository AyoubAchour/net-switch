import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import test from 'node:test';
import { heldSweepLatency, heldUDPSweepGate, ledgerDigest, udpRecoveryGate, udpRecoveryVerdict } from '../tests/windows/udp-capacity.mjs';

test('UDP recovery gate counts a port-0 refusal as OS behaviour only with matching native evidence', () => {
  const cycles = (refused) => [{ reopenAttempts: 2560, reopenRefused: refused }];
  const control = (first, automatic = first) => ({ attempts: 2560, firstRefusals: first, automaticRefusals: automatic });
  const app = [{ Error: 'ENOBUFS', NativeCall: 'connect' }];
  const gate = (change) => udpRecoveryGate({ failures: app, engineCycles: cycles(3), control: control(9), ...change });
  assert.equal(gate().newVerdict, 'reported: Windows automatic port search, also refused in the native control');
  assert.equal(gate().oldVerdict, 'fail');
  assert.equal(gate({ control: control(0) }).newVerdict, 'fail', 'the native control never refused');
  assert.equal(gate({ engineCycles: cycles(12) }).newVerdict, 'fail', 'engine rate above native');
  assert.equal(gate({ failures: [{ Error: 'ETIMEDOUT', NativeCall: 'read' }] }).newVerdict, 'fail', 'not a refusal of the port search');
  assert.equal(gate({ failures: [{ Error: 'ECONNRESET', NativeCall: 'wsarecv' }] }).newVerdict, 'fail', 'reset without an engine bind refusal');
  assert.equal(gate({ failures: [{ Error: 'ECONNRESET', NativeCall: 'wsarecv' }], exhaustions: 1 }).newVerdict,
    'reported: Windows automatic port search, also refused in the native control');
  assert.equal(gate({ contention: true, control: control(0) }).newVerdict, 'reported: another process took the ports');
  assert.equal(udpRecoveryGate({ failures: [], control: control(0) }).newVerdict, 'pass');
});

test('UDP recovery reports a port another process took, and fails everything else', () => {
  // ARM64 job 119178917661: 1 of 512 reopens failed with ENOBUFS while PID
  // 2096 took a dynamic port; the engine (PID 900 here) also grew by its reopens.
  const full = { state: 'complete', families: [{ family: 'ipv4', available: 0 }, { family: 'ipv6', available: 16000 }] };
  const base = { failures: [{ Error: 'ENOBUFS' }], portSpace: full, othersBefore: { 2096: 4, 900: 100 },
    othersAfter: { 2096: 5, 900: 612 }, enginePID: 900, family: 'ipv4' };
  assert.deepEqual(udpRecoveryVerdict(base), { oldVerdict: 'fail', newVerdict: 'reported', grownByOthers: 1, portErrors: true, poolFull: true, available: 0 });
  const verdict = (change) => udpRecoveryVerdict({ ...base, ...change }).newVerdict;
  assert.equal(verdict({ portSpace: { state: 'complete', families: [{ family: 'ipv4', available: 3 }] } }), 'fail', 'the pool had room');
  assert.equal(verdict({ othersAfter: { 2096: 4, 900: 700 } }), 'fail', 'only the engine grew');
  assert.equal(verdict({ failures: [{ Error: 'ENOBUFS' }, { Error: 'ENOBUFS' }] }), 'fail', 'more failures than ports taken');
  assert.equal(verdict({ failures: [{ Error: 'ECONNRESET' }] }), 'fail', 'not a port-exhaustion error');
  assert.equal(verdict({ portSpace: { state: 'partial', families: full.families } }), 'fail', 'incomplete port evidence');
  assert.equal(verdict({ family: 'ipv6' }), 'fail', 'the other family had room');
  assert.equal(verdict({ othersAfter: { 2096: 4, 900: 612, 3100: 1 } }), 'reported', 'a process that appeared inside the window');
  assert.deepEqual(udpRecoveryVerdict({ ...base, failures: [] }).newVerdict, 'pass');
});

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
