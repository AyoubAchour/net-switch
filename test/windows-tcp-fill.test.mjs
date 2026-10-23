import assert from 'node:assert/strict';
import test from 'node:test';
import { clientAllocationFailure, emptyFillEvidence, mergeFillEvidence, openWithClientReattempt,
  windowsErrorName } from '../tests/windows/tcp-fill.mjs';

const at = '2026-10-23T05:00:00.000Z';
const failure = (code, call = 'connect', extra = {}) => ({ source: 'client', code, call, errno: -4082,
  message: `${call} ${code}`, ms: 1.5, local: '198.18.0.1:50000', remote: '198.19.128.2:25000', ...extra });
const opened = () => ({ socket: {}, ms: 2, startMS: 2, endMS: 4 });
// An injected opener: each call returns the next queued result and counts itself.
const injected = (...results) => {
  let calls = 0;
  return { calls: () => calls, open: async () => results[calls++] };
};
const fill = (opener, extra = {}) => ({
  open: opener.open, evidence: emptyFillEvidence(), request: 7, batch: 31, attempt: 992, now: () => at, ...extra,
});

test('a client ENOBUFS on connect gets one reported re-attempt on a fresh socket', async () => {
  const opener = injected({ failure: failure('ENOBUFS') }, opened());
  const spec = fill(opener);
  const result = await openWithClientReattempt(spec);
  const { evidence } = spec;
  assert.equal(result.reattempted, true);
  assert.equal(result.failure, undefined);
  assert.equal(opener.calls(), 2, 'exactly one fresh socket is tried');
  assert.deepEqual(evidence.clientFirstRefusals, { ENOBUFS: 1 });
  assert.deepEqual(evidence.clientReattempts, { ENOBUFS: 1 });
  assert.deepEqual(evidence.clientReattemptSuccesses, { ENOBUFS: 1 });
  assert.deepEqual(evidence.clientReattemptFailures, {});
  assert.deepEqual(evidence.clientFinalRefusals, {});
  assert.equal(evidence.records.length, 1);
  assert.deepEqual(evidence.records[0], {
    at, phase: 'first', request: 7, batch: 31, attempt: 992, code: 'ENOBUFS', name: 'WSAENOBUFS',
    errno: -4082, syscall: 'connect', local: '198.18.0.1:50000', remote: '198.19.128.2:25000',
    ms: 1.5, message: 'connect ENOBUFS', counted: false, outcome: 'reported: succeeded on one re-attempt',
  }, 'the refusal keeps its error name, tuple, batch, attempt and time');
});

test('a client EADDRINUSE on bind that still fails is counted, with both errors recorded', async () => {
  const opener = injected({ failure: failure('EADDRINUSE', 'bind', { local: null }) }, { failure: failure('ENOBUFS') });
  const spec = fill(opener);
  const result = await openWithClientReattempt(spec);
  const { evidence } = spec;
  assert.equal(result.reattempted, true);
  assert.equal(result.failure.code, 'ENOBUFS', 'the re-attempt\'s error is the one that counts');
  assert.equal(opener.calls(), 2);
  assert.deepEqual(evidence.clientFirstRefusals, { EADDRINUSE: 1 });
  assert.deepEqual(evidence.clientReattempts, { EADDRINUSE: 1 });
  assert.deepEqual(evidence.clientReattemptFailures, { EADDRINUSE: 1 });
  assert.deepEqual(evidence.clientFinalRefusals, { ENOBUFS: 1 });
  assert.equal(evidence.records.length, 2);
  assert.equal(evidence.records[0].counted, true, 'the first refusal is counted only because the re-attempt failed');
  assert.equal(evidence.records[0].outcome, 'counted: re-attempt failed');
  assert.equal(evidence.records[1].phase, 'reattempt');
  assert.equal(evidence.records[1].counted, true);
});

test('every other client error counts immediately and is never retried', async () => {
  for (const code of ['ECONNREFUSED', 'ECONNRESET', 'DEADLINE', 'ETIMEDOUT']) {
    const opener = injected({ failure: failure(code) });
    const spec = fill(opener);
    const result = await openWithClientReattempt(spec);
    const { evidence } = spec;
    assert.equal(opener.calls(), 1, code);
    assert.equal(result.reattempted, false, code);
    assert.equal(result.failure.code, code);
    assert.deepEqual(evidence.clientFirstRefusals, {}, code);
    assert.deepEqual(evidence.clientReattempts, {}, code);
    assert.deepEqual(evidence.clientFinalRefusals, { [code]: 1 }, code);
    assert.equal(evidence.records[0].counted, true, code);
  }
});

test('only a source-client bind or connect allocation failure qualifies', () => {
  assert.equal(clientAllocationFailure(failure('ENOBUFS', 'connect')), true);
  assert.equal(clientAllocationFailure(failure('EADDRINUSE', 'bind')), true);
  assert.equal(clientAllocationFailure(failure('ENOBUFS', 'wsarecv')), false, 'not the app\'s bind or connect');
  assert.equal(clientAllocationFailure({ ...failure('ENOBUFS'), call: undefined }), false, 'an unknown call is not assumed client-side');
  assert.equal(clientAllocationFailure(failure('ENOBUFS', 'connect', { source: 'engine' })), false, 'an engine refusal never qualifies');
  assert.equal(clientAllocationFailure(failure('ECONNRESET', 'connect')), false);
  assert.equal(clientAllocationFailure(null), false);
});

test('evidence merges across fill calls and names the Windows errors', () => {
  assert.equal(windowsErrorName('ENOBUFS'), 'WSAENOBUFS');
  assert.equal(windowsErrorName('EADDRINUSE'), 'WSAEADDRINUSE');
  assert.equal(windowsErrorName('ECONNRESET'), null);
  const target = emptyFillEvidence();
  const first = emptyFillEvidence();
  first.clientFirstRefusals.ENOBUFS = 1; first.clientReattempts.ENOBUFS = 1;
  first.clientReattemptSuccesses.ENOBUFS = 1; first.records.push({ request: 1 });
  const second = emptyFillEvidence();
  second.clientFirstRefusals.EADDRINUSE = 2; second.clientReattempts.EADDRINUSE = 2;
  second.clientReattemptFailures.EADDRINUSE = 2; second.clientFinalRefusals.ENOBUFS = 2;
  second.records.push({ request: 2 }, { request: 3 });
  mergeFillEvidence(target, first);
  mergeFillEvidence(target, second);
  assert.deepEqual(target.clientFirstRefusals, { ENOBUFS: 1, EADDRINUSE: 2 });
  assert.deepEqual(target.clientReattempts, { ENOBUFS: 1, EADDRINUSE: 2 });
  assert.deepEqual(target.clientReattemptFailures, { EADDRINUSE: 2 });
  assert.deepEqual(target.clientFinalRefusals, { ENOBUFS: 2 });
  assert.deepEqual(target.records.map((item) => item.request), [1, 2, 3]);
  mergeFillEvidence(target, undefined);
  assert.deepEqual(target.clientFinalRefusals, { ENOBUFS: 2 }, 'missing evidence changes nothing');
});
