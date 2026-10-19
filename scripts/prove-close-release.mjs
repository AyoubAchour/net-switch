// A green proof requires each named regression to fail with release disabled.
// Build failures, skipped tests, missing tests and timeouts are not evidence.
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';

const paths = ['app_fin', 'remote_fin', 'simultaneous', 'app_rst', 'remote_rst', 'policy'];
const expected = ['total', 'app', 'unknown'].flatMap(cap => paths.map(path => `TestCloseAdmission/${cap}/${path}`));
expected.push('TestCloseIdleAdmission', 'TestCloseBeforeFinalACK/last_ack', 'TestCloseBeforeFinalACK/closing', 'TestCloseHandshakeCap/1', 'TestCloseHandshakeCap/2048');
expected.push('TestCloseKeepsQueuedDataCounted/last_ack', 'TestCloseKeepsQueuedDataCounted/closing', 'TestCloseRSTDuringHandshake');
expected.push('TestCloseHandshakeCompletionOwnsRelease');
expected.push('TestCloseHandshakeBeforeHangupNotification/handshake', 'TestCloseHandshakeBeforeHangupNotification/setup');
const result = spawnSync(process.env.GO_BINARY || 'go', [
  'test', '-json', '-count=1', '-timeout=120s', '-tags=close_admission_disabled',
  '-run', '^Test(CloseAdmission|CloseIdleAdmission|CloseBeforeFinalACK|CloseHandshakeCap|CloseKeepsQueuedDataCounted|CloseRSTDuringHandshake|CloseHandshakeCompletionOwnsRelease|CloseHandshakeBeforeHangupNotification)$',
  './internal/engine/stack',
], { encoding: 'utf8', windowsHide: true, maxBuffer: 16 << 20 });
assert.equal(result.error, undefined, result.error?.message);
assert.equal(result.status, 1, `mutated tests must fail: ${result.stderr}\n${result.stdout}`);
const events = result.stdout.trim().split(/\r?\n/).map(line => JSON.parse(line));
assert.ok(!events.some(e => /panic:|test timed out|build failed/.test(e.Output || '')), result.stdout);
for (const name of expected) {
  assert.equal(events.filter(e => e.Test === name && e.Action === 'run').length, 1, `${name} did not run exactly once`);
  const failed = events.filter(e => e.Test === name && e.Action === 'fail');
  assert.equal(failed.length, 1, `${name} did not fail\n${result.stdout}`);
  const messages = events.filter(e => e.Test === name && e.Output).map(e => e.Output.replace(/^.*\.go:\d+: /, '').trim());
  const evidence = messages.filter(message => /retir|retained|unexpected RST|false close rejection|gate/.test(message));
  assert.ok(evidence.length > 0, `${name} failed without the expected admission evidence`);
  console.log(`PROOF ${name}: failed in ${failed[0].Elapsed}s; ${evidence[0]}`);
}
console.log(`REVERT PROOF: ${expected.length}/${expected.length} close-path cases failed as required; no skipped or missing cases.`);
