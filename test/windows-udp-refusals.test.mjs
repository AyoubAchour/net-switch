import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import test from 'node:test';
import { udpRefusalAttribution } from '../tests/windows/udp-capacity.mjs';

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
