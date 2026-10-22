import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import test from 'node:test';
import { engineBindDelta, flowReconciliation, heldSweepLatency, heldUDPSweepGate, ledgerDigest, portRecoveryGate, recoveryWindowMS,
  reopenTimings, udpControlGate, udpRecoveryVerdict } from '../tests/windows/udp-capacity.mjs';

// 256 reopens: 254 first-attempt successes of 20 ms, and the given extras.
const reopens = (...extra) => [...Array.from({ length: 256 - extra.length }, () => ({ ms: 20, reattempted: false, ok: true })), ...extra];

test('the amended recovery gate requires no leak, one re-attempt, every reopen within the window and no final engine bind refusal', () => {
  const refused = [{ call: 'connect', code: 'ENOBUFS' }, { call: 'wsarecv', code: 'ECONNRESET' }];
  const retried = (ms = 300, ok = true) => ({ ms, reattempted: true, ok });
  const base = { requested: 256, firstFailures: refused, reopens: reopens(retried(), retried()), elapsedMS: 300,
    leak: { ok: true }, engineBinds: { firstRefusals: 3, finalFailures: 0 } };
  const gate = (change) => portRecoveryGate({ ...base, ...change });
  assert.equal(gate().newVerdict, 'pass');
  assert.equal(gate().oldVerdict, 'fail', 'first-attempt refusals failed the old check');
  assert.deepEqual(gate().reported.byCall, { 'connect ENOBUFS': 1, 'wsarecv ECONNRESET': 1 });
  assert.equal(gate().reopened, 256);
  assert.equal(gate({ reopens: reopens(retried(), retried(300, false)) }).newVerdict, 'fail', 'a reopen still failing after its re-attempt');
  assert.equal(gate({ reopens: reopens(retried(), { ms: null, reattempted: false, ok: false }) }).newVerdict, 'fail', 'a refusal without its re-attempt');
  assert.equal(gate({ reopens: reopens(retried(), retried(), retried()) }).newVerdict, 'fail', 'more re-attempts than refusals');
  assert.equal(gate({ reopens: reopens(retried(), retried(recoveryWindowMS + 0.001)) }).newVerdict, 'fail',
    're-attempt path: a re-attempted reopen outside the window from its original start');
  assert.equal(gate({ reopens: reopens(retried(), retried(recoveryWindowMS)) }).newVerdict, 'pass', 'the window is inclusive');
  assert.equal(gate({ reopens: reopens(retried()) }).newVerdict, 'fail', 'fewer reopens than requested');
  assert.equal(gate({ leak: undefined }).newVerdict, 'fail', 'no leak evidence');
  assert.equal(gate({ engineBinds: { firstRefusals: 3, finalFailures: 1 } }).newVerdict, 'fail', 'an engine bind ended refused');
  // Review of PR #46: with no refusal the old gate skipped the window, so a
  // 1.5 s (or 5 s) reopen passed. Every reopen is timed now.
  const noRefusal = { firstFailures: [], reopens: reopens() };
  assert.equal(gate(noRefusal).newVerdict, 'pass');
  assert.equal(gate(noRefusal).oldVerdict, 'pass');
  assert.equal(gate({ ...noRefusal, reopens: reopens({ ms: 1500, reattempted: false, ok: true }) }).newVerdict, 'fail',
    'no-refusal path: one first-attempt success over the window');
  assert.equal(gate({ ...noRefusal, reopens: reopens({ ms: 5000, reattempted: false, ok: true }) }).newVerdict, 'fail',
    'no-refusal path: the 5 s reopen the old test let pass');
  assert.equal(gate({ ...noRefusal, reopens: reopens({ ms: 1500, reattempted: false, ok: true }) }).slowReopens, 1);
});

test('reopen timings time each reopen alone and a re-attempt from its original start', () => {
  // Two batches of the same reopen call: the first at 0-20 ms, the second at
  // 900-930 ms. One first attempt failed at 905 ms; its re-attempt ran
  // 1,000-1,050 ms.
  const first = [{ startMS: 0, endMS: 20, ok: true }, { startMS: 900, endMS: 930, ok: true }, { startMS: 900, endMS: 905, ok: false }];
  const timed = reopenTimings(first, [{ startMS: 1000, endMS: 1050, ok: true }]);
  assert.deepEqual(timed, [{ ms: 20, reattempted: false, ok: true }, { ms: 30, reattempted: false, ok: true }, { ms: 150, reattempted: true, ok: true }],
    'the second batch is not charged the first batch\'s wait, and the re-attempt keeps its original start');
  assert.deepEqual(reopenTimings(first), [{ ms: 20, reattempted: false, ok: true }, { ms: 30, reattempted: false, ok: true },
    { ms: null, reattempted: false, ok: false }], 'a refusal with no re-attempt stays a failed reopen');
  const gate = portRecoveryGate({ requested: 3, firstFailures: [{ call: 'connect', code: 'ENOBUFS' }],
    reopens: reopenTimings(first, [{ startMS: 1950, endMS: 1960, ok: true }]), leak: { ok: true }, engineBinds: { finalFailures: 0 } });
  assert.equal(gate.newVerdict, 'fail', 'a re-attempt ending 1,060 ms after its original start misses the window');
});

test('engine bind deltas count the protocol under recovery and list final refusals with their flows', () => {
  const retries = (first, final) => ({ firstRefusals: first, freshAttempts: first * 2, recoveredOnFreshAttempt: [first, 0, 0, 0], finalFailures: final });
  const refusal = (id) => ({ protocol: 'tcp', kind: 'flow', app: `C:\\apps\\${id}.exe`, destination: '198.19.128.2:25000' });
  const before = { tcpDialRetries: retries(10, 2), udpBindRetries: retries(5, 1), finalPortRefusals: { count: 3, recent: [refusal('a'), refusal('b'), refusal('c')] } };
  const after = { tcpDialRetries: retries(13, 3), udpBindRetries: retries(9, 4), finalPortRefusals: { count: 7, recent: [refusal('a'), refusal('b'), refusal('c'), refusal('d'), refusal('e'), refusal('f'), refusal('g')] } };
  const tcp = engineBindDelta(before, after, 'tcp');
  assert.equal(tcp.firstRefusals, 3);
  assert.equal(tcp.finalFailures, 1, 'only TCP final failures are the TCP gate input');
  assert.equal(tcp.otherProtocolFinalFailures, 3);
  assert.deepEqual(tcp.finalRefusals.map((item) => item.app), ['C:\\apps\\d.exe', 'C:\\apps\\e.exe', 'C:\\apps\\f.exe', 'C:\\apps\\g.exe']);
  assert.deepEqual(tcp.tcp.recoveredOnFreshAttempt, [3, 0, 0, 0]);
  assert.equal(engineBindDelta(before, after, 'udp').finalFailures, 3);
  assert.deepEqual(engineBindDelta(after, after, 'tcp').finalRefusals, [], 'no new final refusal lists none');
  const gate = (engineBinds) => portRecoveryGate({ requested: 256, firstFailures: [], reopens: reopens(), leak: { ok: true }, engineBinds }).newVerdict;
  assert.equal(gate(engineBindDelta(before, { ...after, tcpDialRetries: retries(13, 2) }, 'tcp')), 'pass', 'first refusals alone never fail the gate');
  assert.equal(gate(tcp), 'fail', 'a TCP dial that ended refused fails the TCP gate');
});

test('flow reconciliation fails a counter-only leak and a stale-record leak', () => {
  const peer = { host: '198.19.128.2', ports: [25000, 25001] };
  const tcp = (id, app = 'C:\\case\\capacity-app-0.exe') => ({ id, protocol: 'tcp', app: { path: app }, destination: `${peer.host}:25000` });
  const udp = (id) => ({ id, protocol: 'udp', app: { path: 'C:\\case\\udp-capacity-app-1.exe' }, destination: '198.19.128.2:26000' });
  const background = [{ id: 900, protocol: 'udp', app: { path: 'c:\\windows\\system32\\svchost.exe' }, destination: '10.1.0.1:53' },
    { id: 901, protocol: 'tcp', handshake: true, unresolved: true, destination: '172.183.7.194:443' }];
  // As in capacity.mjs.
  const tcpCohort = (flow) => /[\\/]capacity-app-\d+\.exe$/i.test(flow.app?.path ?? '') && peer.ports.some((port) => flow.destination === `${peer.host}:${port}`);
  const udpCohort = (flow) => flow.protocol === 'udp' && flow.destination === '198.19.128.2:26000';
  // As in capacity.mjs: a test app's handshake, or an unresolved one to the peer.
  const ourHandshake = (flow) => (flow.unresolved ? flow.destination.startsWith(`${peer.host}:`) : /[\\/]case[\\/]/.test(flow.app?.path ?? ''));
  const records = [...Array.from({ length: 100 }, (_, i) => tcp(i)), ...Array.from({ length: 50 }, (_, i) => udp(100 + i)), ...background];
  const counted = { flows: records.length, udp: 51, handshakes: 1 };
  const reconcile = (change) => flowReconciliation({ records, counted, tcpCohort, udpCohort, ourHandshake, clientsTCP: 100, peerTCP: 100, clientsUDP: 50, ...change });
  const exact = reconcile();
  assert.equal(exact.pass, true, JSON.stringify(exact.checks));
  assert.equal(exact.background.length, 2, 'background flows are enumerated');
  // Counter-only leak: 100 admission charges with no record behind them.
  const counterLeak = reconcile({ counted: { ...counted, flows: counted.flows + 100 } });
  assert.equal(counterLeak.pass, false);
  assert.equal(counterLeak.checks.countersMatchRecords, false);
  assert.equal(counterLeak.checks.gaugesEqualCohortsAndBackground, false);
  // Stale-record leak: 100 records (and their charges) whose connections are
  // gone at the clients and at the peer.
  const stale = [...records, ...Array.from({ length: 100 }, (_, i) => tcp(1000 + i))];
  const recordLeak = reconcile({ records: stale, counted: { ...counted, flows: stale.length } });
  assert.equal(recordLeak.pass, false);
  assert.equal(recordLeak.checks.tcpEqualsClients, false);
  assert.equal(recordLeak.checks.tcpEqualsPeer, false);
  assert.equal(recordLeak.checks.countersMatchRecords, true, 'the table agrees with itself; only the independent counts catch it');
  // The old check, Flows >= held TCP with UDP inside Flows, passed both leaks.
  assert(counted.flows + 100 >= 100 && stale.length >= 100);
  assert.equal(reconcile({ peerTCP: 99 }).checks.tcpEqualsPeer, false, 'a connection lost at the peer');
  assert.equal(reconcile({ counted: { ...counted, udp: 52 } }).pass, false, 'a leaked UDP charge');
  assert.equal(reconcile({ counted: { ...counted, handshakes: 0 } }).pass, false, 'a handshake counted without its record');
  assert.equal(reconcile({ counted: undefined }).pass, false, 'no counts from the engine');
  assert.equal(exact.foreignHandshakes.length, 1, 'Windows\' own unresolved handshake elsewhere is reported, not counted');
  assert.equal(exact.ourHandshakes.length, 0);
});

test('flow reconciliation fails a leftover unresolved handshake to the test peer even when every count matches', () => {
  // Review of 822789db: after recovery, clients, peer and the TCP cohort all
  // agree, but one earlier attempt left an unresolved handshake to the peer.
  // It has no app, so it sits in the background, and its charge matches its
  // record; only the handshake check sees it.
  const peer = '198.19.128.2';
  const tcp = (id) => ({ id, protocol: 'tcp', app: { path: 'C:\\case\\capacity-app-0.exe' }, destination: `${peer}:25000` });
  const leftover = { id: 999, protocol: 'tcp', handshake: true, unresolved: true, source: '198.18.0.1:61000', destination: `${peer}:25003`,
    start: new Date(1_000_000).toISOString() };
  const records = [...Array.from({ length: 10 }, (_, i) => tcp(i)), leftover];
  const reconcile = (records) => flowReconciliation({ records, counted: { flows: records.length, udp: 0, handshakes: records.filter((f) => f.handshake).length },
    tcpCohort: (flow) => Boolean(flow.app) && flow.destination.startsWith(`${peer}:`), udpCohort: () => false,
    ourHandshake: (flow) => (flow.unresolved ? flow.destination.startsWith(`${peer}:`) : true),
    clientsTCP: 10, peerTCP: 10, clientsUDP: 0, now: 1_250_000 });
  const result = reconcile(records);
  const { noOwnHandshakes, ...counts } = result.checks;
  assert(Object.values(counts).every(Boolean), `every count matches: ${JSON.stringify(counts)}`);
  assert.equal(noOwnHandshakes, false);
  assert.equal(result.pass, false, 'the leftover handshake fails the reconciliation');
  assert.deepEqual(result.ourHandshakes, [{ id: 999, app: '', resolved: false, source: '198.18.0.1:61000', destination: `${peer}:25003`, line: '', ageMS: 250_000 }]);
  assert.equal(reconcile(records.slice(0, 10)).pass, true, 'without it the same state passes');
  const foreign = { ...leftover, destination: '172.183.7.194:443' };
  assert.equal(reconcile([...records.slice(0, 10), foreign]).pass, true, 'an unresolved handshake elsewhere is Windows\' own: reported only');
});

test('the previous UDP control gate counts a port-0 refusal as OS behaviour only with matching native evidence', () => {
  const cycles = (refused) => [{ reopenAttempts: 2560, reopenRefused: refused }];
  const control = (first, automatic = first) => ({ attempts: 2560, firstRefusals: first, automaticRefusals: automatic });
  const app = [{ Error: 'ENOBUFS', NativeCall: 'connect' }];
  const gate = (change) => udpControlGate({ failures: app, engineCycles: cycles(3), control: control(9), ...change });
  assert.equal(gate().newVerdict, 'reported: Windows automatic port search, also refused in the native control');
  assert.equal(gate().oldVerdict, 'fail');
  assert.equal(gate({ control: control(0) }).newVerdict, 'fail', 'the native control never refused');
  assert.equal(gate({ engineCycles: cycles(12) }).newVerdict, 'fail', 'engine rate above native');
  assert.equal(gate({ failures: [{ Error: 'ETIMEDOUT', NativeCall: 'read' }] }).newVerdict, 'fail', 'not a refusal of the port search');
  assert.equal(gate({ failures: [{ Error: 'ECONNRESET', NativeCall: 'wsarecv' }] }).newVerdict, 'fail', 'reset without an engine bind refusal');
  assert.equal(gate({ failures: [{ Error: 'ECONNRESET', NativeCall: 'wsarecv' }], exhaustions: 1 }).newVerdict,
    'reported: Windows automatic port search, also refused in the native control');
  assert.equal(gate({ contention: true, control: control(0) }).newVerdict, 'reported: another process took the ports');
  assert.equal(udpControlGate({ failures: [], control: control(0) }).newVerdict, 'pass');
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
