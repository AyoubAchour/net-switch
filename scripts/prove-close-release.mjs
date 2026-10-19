// A green proof requires named behavioral failures, not build errors or skips.
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';

const caps = ['total', 'app', 'unknown'];
const releaseCases = caps.flatMap(cap => ['app_fin', 'app_rst', 'remote_rst', 'policy'].map(path => `TestCloseAdmission/${cap}/${path}`));
releaseCases.push('TestCloseIdleAdmission', 'TestCloseBeforeFinalACK/last_ack', 'TestCloseBeforeFinalACK/closing', 'TestCloseHandshakeCap/1', 'TestCloseHandshakeCap/2048');
releaseCases.push('TestCloseKeepsQueuedDataCounted/last_ack', 'TestCloseKeepsQueuedDataCounted/closing', 'TestCloseRSTDuringHandshake');
releaseCases.push('TestCloseHandshakeCompletionOwnsRelease');
releaseCases.push('TestCloseHandshakeBeforeHangupNotification/handshake', 'TestCloseHandshakeBeforeHangupNotification/setup');

// These paths already release through #34's TIME_WAIT policy. Keep that older
// behavior enabled and prove it still passes in the narrower release mutation.
const preserved = caps.flatMap(cap => ['remote_fin', 'simultaneous'].map(path => `TestCloseAdmission/${cap}/${path}`));
preserved.push('TestTimeWaitFinalACKReleasesAdmission/cap_0', 'TestTimeWaitFinalACKReleasesAdmission/cap_1');
const fenceCases = caps.flatMap(cap => ['app_rst', 'remote_fin'].map(path => `TestCloseAdmission/${cap}/${path}`));
fenceCases.push('TestCloseRSTDuringHandshake');

function prove(tag, run, failures, passes = []) {
  const result = spawnSync(process.env.GO_BINARY || 'go', [
    'test', '-json', '-count=1', '-timeout=120s', `-tags=${tag}`,
    '-run', run, './internal/engine/stack',
  ], { encoding: 'utf8', windowsHide: true, maxBuffer: 16 << 20 });
  assert.equal(result.error, undefined, result.error?.message);
  assert.equal(result.status, 1, `mutated tests must fail: ${result.stderr}\n${result.stdout}`);
  const events = result.stdout.trim().split(/\r?\n/).map(line => JSON.parse(line));
  assert.ok(!events.some(e => /panic:|test timed out|build failed/.test(e.Output || '')), result.stdout);
  for (const [names, action] of [[failures, 'fail'], [passes, 'pass']]) {
    for (const name of names) {
      assert.equal(events.filter(e => e.Test === name && e.Action === 'run').length, 1, `${name} did not run exactly once`);
      const ended = events.filter(e => e.Test === name && e.Action === action);
      assert.equal(ended.length, 1, `${name} did not ${action}\n${result.stdout}`);
      if (action === 'fail') {
        const messages = events.filter(e => e.Test === name && e.Output).map(e => e.Output.replace(/^.*\.go:\d+: /, '').trim());
        const evidence = messages.filter(message => /retir|retained|unexpected RST|false close rejection|gate/.test(message));
        assert.ok(evidence.length > 0, `${name} failed without admission evidence\n${result.stdout}`);
        console.log(`PROOF ${tag} ${name}: failed in ${ended[0].Elapsed}s; ${evidence[0]}`);
      } else {
        console.log(`PRESERVED ${tag} ${name}: passed in ${ended[0].Elapsed}s`);
      }
    }
  }
  console.log(`REVERT PROOF ${tag}: ${failures.length}/${failures.length} cases failed as required; ${passes.length}/${passes.length} older cases preserved; no skipped or missing cases.`);
}

prove('close_admission_disabled', '^Test(CloseAdmission|CloseIdleAdmission|CloseBeforeFinalACK|CloseHandshakeCap|CloseKeepsQueuedDataCounted|CloseRSTDuringHandshake|CloseHandshakeCompletionOwnsRelease|CloseHandshakeBeforeHangupNotification|TimeWaitFinalACKReleasesAdmission)$', releaseCases, preserved);
prove('close_fence_disabled', '^Test(CloseAdmission|CloseRSTDuringHandshake)$', fenceCases);
