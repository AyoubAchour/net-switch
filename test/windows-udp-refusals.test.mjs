import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import test from 'node:test';
import { clientPortChoiceRefusal, retryFillRefusals, udpFloorShortfall, udpRefusalAttribution } from '../tests/windows/udp-capacity.mjs';

const resets = (n, ports = n) => Array.from({ length: n }, (_, i) => ({
  Error: 'ECONNRESET', Token: i.toString(16).padStart(16, '0'), Local: `198.18.0.1:${40000 + i % ports}`, Remote: '198.19.128.2:26000',
}));
const stats = (ports = 0, generations = 0, identity = 0, attempts = []) => ({
  udpSocketExhaustions: ports, udpGenerationMissing: generations,
  udpBindRetries: { finalFailures: ports },
  ownerLookup: { udpGenerationRefusals: generations },
  flows: { RefusedUDP: { UnknownUDP: identity } },
  udpRefusalDatagrams: { count: attempts.length, portExhaustionSetups: ports, recent: attempts.map((a, i) => ({
    sequence: i + 1, source: a.Local, destination: a.Remote, sent: true,
    payloadSHA256: createHash('sha256').update(Buffer.concat([Buffer.from('NSUDPCAP'), Buffer.from(a.Token, 'hex')])).digest('hex'),
    reason: 'port-exhaustion', path: i < ports ? 'pending' : 'negative-cache',
  })) },
});

test('78 distinct attempts reusing 20 exhausted sources require 78 individual engine receipts', () => {
  const attempts = resets(78, 20), after = stats(20, 0, 0, attempts);
  const result = udpRefusalAttribution(attempts, stats(), after);
  assert.equal(result.passed, true);
  assert.equal(result.distinctResetSources, 20);
  assert.deepEqual(result.paths, { pending: 20, 'negative-cache': 58 });
  after.udpRefusalDatagrams.recent.pop();
  assert.equal(udpRefusalAttribution(attempts, stats(), after).passed, false, 'a reused port alone does not explain a reset');
});

test('every client reset requires its own matching token, source and destination', () => {
  const attempts = resets(2, 1);
  for (const field of ['source', 'destination', 'payloadSHA256', 'sequence']) {
    const after = stats(1, 0, 0, attempts);
    after.udpRefusalDatagrams.recent[1][field] = after.udpRefusalDatagrams.recent[0][field];
    if (field === 'source' || field === 'destination') after.udpRefusalDatagrams.recent[1][field] += '9';
    assert.equal(udpRefusalAttribution(attempts, stats(), after).passed, false, field);
  }
  const after = stats(1, 0, 0, attempts);
  assert.equal(udpRefusalAttribution(attempts, after, after).passed, false, 'previous-batch records cannot be reused');
  after.udpRefusalDatagrams.recent[0].sent = false;
  assert.equal(udpRefusalAttribution(attempts, stats(), after).passed, false, 'a dropped engine output cannot explain a reset');
  delete after.udpRefusalDatagrams;
  assert.equal(udpRefusalAttribution(attempts, stats(), after).passed, false, 'missing stats cannot pass');
});

test('cached non-exhaustion causes fail even beside a real exhausted bind', () => {
  const attempts = resets(2);
  for (const reason of ['generation', 'admission', 'policy-or-owner-budget', 'socket-open', 'send', 'peer-error', 'unclassified']) {
    const after = stats(1, 0, 0, attempts);
    after.udpRefusalDatagrams.recent[1].reason = reason;
    const result = udpRefusalAttribution(attempts, stats(), after);
    assert.equal(result.passed, false, reason);
    assert.equal(result.nonExhaustion[0].reason, reason);
  }
});

test('new exhausted setups must match final native exhaustion counters, cached replies do not invent binds', () => {
  const attempts = resets(2, 1), before = stats(1);
  const after = stats(1, 0, 0, attempts);
  after.udpRefusalDatagrams.recent.forEach(r => r.path = 'negative-cache');
  assert.equal(udpRefusalAttribution(attempts, before, after).passed, true);
  after.udpRefusalDatagrams.portExhaustionSetups++;
  assert.equal(udpRefusalAttribution(attempts, before, after).passed, false);
  const final = stats(2, 0, 0, attempts);
  final.udpBindRetries.finalFailures = 1;
  assert.equal(udpRefusalAttribution(attempts, stats(), final).passed, false);
});

test('generation and identity refusals fail independently of port exhaustion', () => {
  const attempts = resets(31);
  assert.equal(udpRefusalAttribution(attempts, stats(), stats(0, 31, 0, attempts)).passed, false);
  assert.equal(udpRefusalAttribution(attempts, stats(), stats(31, 0, 1, attempts)).passed, false);
});

test('identity expiry with a generation remains admission; client connect exhaustion needs no engine bind', () => {
  const after = stats();
  after.ownerLookup.udpIdentityExpiredGeneration = 31;
  after.ownerLookup.udpHolds = 31;
  after.ownerLookup.udpHeldGenerations = 31;
  assert.equal(udpRefusalAttribution([{ Error: 'ENOBUFS' }], stats(), after).passed, true);
});

const refusal = (NativeCall = 'connect', Error = 'ENOBUFS') => ({ NativeCall, Error });
const success = () => ({ NativeCall: 'connect', Error: '' });
const queued = (rounds) => {
  const calls = [];
  return { calls, reopen: async (count) => {
    calls.push(count);
    return { result: { attempts: rounds.shift() }, refused: [], stats: { flows: calls.length } };
  } };
};

test('only an app bind or connect allocation failure is a retryable port choice', () => {
  assert.equal(clientPortChoiceRefusal({ NativeCall: 'bind', Error: 'EADDRINUSE' }), true);
  assert.equal(clientPortChoiceRefusal({ NativeCall: 'connect', Error: 'ENOBUFS' }), true);
  assert.equal(clientPortChoiceRefusal({ NativeCall: 'send', Error: 'ENOBUFS' }), false);
  assert.equal(clientPortChoiceRefusal({ NativeCall: 'connect', Error: 'ECONNRESET' }), false);
  assert.equal(clientPortChoiceRefusal({ NativeCall: 'connect', Error: 'ECONNREFUSED' }), false);
  assert.equal(clientPortChoiceRefusal(undefined), false);
});

test('a client port refusal recovers on a later fresh attempt', async () => {
  const { reopen, calls } = queued([[refusal(), success()], [refusal()], [success()]]);
  const retry = await retryFillRefusals({ refused: [refusal(), refusal()], room: true, available: 2150, reopen, sleep: async () => {} });
  assert.equal(retry.refused.length, 0);
  assert.equal(retry.record.freshAttempts, 3);
  assert.deepEqual([...retry.record.recoveredOnFreshAttempt], [1, 0, 1, 0]);
  assert.deepEqual(retry.record.attemptsPerRefusal, [4, 2]);
  assert.equal(retry.record.finalClientRefusals, 0);
  assert.deepEqual(calls, [2, 1, 1]);
});

test('four refused fresh attempts are recorded, then the floor verdict decides the run', async () => {
  const { reopen, calls } = queued([[refusal()], [refusal()], [refusal()], [refusal()], [refusal()]]);
  const retry = await retryFillRefusals({ refused: [refusal()], room: true, available: 2150, reopen, sleep: async () => {} });
  assert.equal(retry.refused.length, 1);
  assert.equal(retry.record.freshAttempts, 4);
  assert.deepEqual([...retry.record.recoveredOnFreshAttempt], [0, 0, 0, 0]);
  assert.deepEqual(retry.record.attemptsPerRefusal, [5]);
  assert.equal(retry.record.finalClientRefusals, 1);
  assert.deepEqual(retry.record.finalRefused, [{ call: 'connect', code: 'ENOBUFS' }]);
  assert.deepEqual([...retry.record.backoffMS], [10, 20, 40, 80]);
  assert.deepEqual(calls, [1, 1, 1, 1]);
});

test('exhausted client retries still pass when the fill clears the floor', () => {
  const record = { room: true, finalClientRefusals: 1, finalRefused: [{ call: 'connect', code: 'ENOBUFS' }],
    freshAttempts: 4, maxFreshAttempts: 4, available: 6 };
  assert.equal(udpFloorShortfall({ floor: 7636, fillReattempts: [record] }, 8030), null);
});

test('a shortfall after client refusals with room names the client case and numbers', () => {
  const record = { room: true, finalClientRefusals: 1, finalRefused: [{ call: 'connect', code: 'ENOBUFS' }],
    freshAttempts: 4, maxFreshAttempts: 4, available: 2150 };
  const message = udpFloorShortfall({ floor: 7636, fillReattempts: [record] }, 6911);
  assert.match(message, /UDP held 6911, below the 95% native layout floor 7636/);
  assert.match(message, /client-side ENOBUFS with free ports/);
  assert.match(message, /1 flow\(s\) still refused after 4 of 4 fresh attempts/);
  assert.match(message, /2150 IPv4 dynamic ports were free/);
});

test('a shortfall without client port exhaustion keeps the generic floor message', () => {
  const record = { room: false, finalClientRefusals: 0, finalRefused: [], freshAttempts: 0, maxFreshAttempts: 4, available: 0 };
  const message = udpFloorShortfall({ floor: 7636, fillReattempts: [record] }, 6911);
  assert.equal(message, 'UDP held 6911, below the 95% native layout floor 7636');
});

test('an engine-side refusal stops immediately and is never called client port exhaustion', async () => {
  const { reopen, calls } = queued([[refusal('connect', 'ECONNRESET')], [success()]]);
  const retry = await retryFillRefusals({ refused: [refusal('connect', 'ECONNRESET')], room: true, available: 900, reopen, sleep: async () => {} });
  assert.equal(calls.length, 1);
  assert.equal(retry.record.freshAttempts, 1);
  assert.equal(retry.record.finalClientRefusals, 0);
  assert.equal(retry.record.finalOtherRefusals, 1);
});

test('a full pool gets no fresh attempt', async () => {
  const { reopen, calls } = queued([]);
  const retry = await retryFillRefusals({ refused: [refusal()], room: false, available: 0, reopen, sleep: async () => {} });
  assert.equal(calls.length, 0);
  assert.equal(retry.record.freshAttempts, 0);
  assert.equal(retry.record.finalClientRefusals, 1);
});
