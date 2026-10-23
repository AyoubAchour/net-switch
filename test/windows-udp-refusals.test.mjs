import assert from 'node:assert/strict';
import test from 'node:test';
import { udpRefusalAttribution } from '../tests/windows/udp-capacity.mjs';

const resets = (n) => Array.from({ length: n }, () => ({ Error: 'ECONNRESET' }));
const stats = (ports = 0, generations = 0, identity = 0) => ({
  udpSocketExhaustions: ports, udpGenerationMissing: generations,
  udpBindRetries: { finalFailures: ports },
  ownerLookup: { udpGenerationRefusals: generations },
  flows: { RefusedUDP: { UnknownUDP: identity } },
});

test('every client reset needs a final exhausted bind in its own batch', () => {
  assert.equal(udpRefusalAttribution(resets(31), stats(), stats(31)).passed, true);
  assert.equal(udpRefusalAttribution(resets(31), stats(), stats(1)).passed, false);
  assert.equal(udpRefusalAttribution(resets(1), stats(1), stats(1)).passed, false, 'an old exhaustion cannot excuse a new reset');
  const after = stats(1);
  after.udpBindRetries.finalFailures = 0;
  assert.equal(udpRefusalAttribution(resets(1), stats(), after).passed, false, 'a recovered bind is not a final refusal');
});

test('the diagnosed 31 missing generations fail independently of an exhausted bind', () => {
  const result = udpRefusalAttribution(resets(31), stats(), stats(0, 31));
  assert.equal(result.generationRefusals, 31);
  assert.equal(result.portExhaustions, 0);
  assert.equal(result.passed, false);
  assert.equal(udpRefusalAttribution(resets(32), stats(), stats(1, 31)).passed, false);
  assert.equal(udpRefusalAttribution(resets(1), stats(), stats(0, 0, 1)).passed, false);
});

test('identity expiry with a generation remains an admission; client connect exhaustion needs no engine bind', () => {
  const after = stats();
  after.ownerLookup.udpIdentityExpiredGeneration = 31;
  after.ownerLookup.udpHolds = 31;
  after.ownerLookup.udpHeldGenerations = 31;
  const result = udpRefusalAttribution([{ Error: 'ENOBUFS' }], stats(), after);
  assert.equal(result.passed, true);
  assert.equal(result.identityExpiredWithGeneration, 31);
  assert.equal(result.heldGenerations, 31);
});
