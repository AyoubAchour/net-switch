// Temporary hosted round-2 proof. Each mutation removes exactly one guard in
// the generator, never edits either generated dependency tree by hand.
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';

const go = process.env.GO_BINARY || 'go';
function run(exe, args, env) {
  const r = spawnSync(exe, args, { env, encoding: 'utf8', windowsHide: true, maxBuffer: 16 << 20 });
  assert.ifError(r.error);
  return r;
}
function generate(mutation) {
  const env = { ...process.env, NETSWITCH_RTO_MUTATION: mutation };
  for (const [exe, args] of [[process.execPath, ['scripts/generate-gvisor.mjs']], [go, ['mod', 'vendor']]]) {
    const r = run(exe, args, env);
    assert.equal(r.status, 0, r.stdout + r.stderr);
    process.stdout.write(r.stdout);
  }
}
const cases = ['rack', 'sack', 'rack_reordered', 'rack_timer'];
const targets = {
  ack: ['rack', /ACK-driven recovery stalled/],
  timer: ['rack_timer', /reordering timer replaced timeout recovery/],
  duplicate: ['rack_reordered', /ACK-driven recovery stalled/],
};
try {
  for (const mutation of ['', 'ack', 'timer', 'duplicate']) {
    generate(mutation);
    const count = mutation ? 10 : 25;
    const r = run(go, ['test', '-json', `-count=${count}`, '-timeout=120s',
      '-run=^TestTCPRecoveryAfterLostWindow$', './internal/engine/stack'], process.env);
    assert.equal(r.status, mutation ? 1 : 0, r.stdout + r.stderr);
    const events = r.stdout.trim().split(/\r?\n/).map(line => JSON.parse(line));
    assert.ok(!events.some(e => /panic:|test timed out|build failed/.test(e.Output || '')), r.stdout);
    for (const name of cases) {
      const full = `TestTCPRecoveryAfterLostWindow/${name}`;
      const selected = events.filter(e => e.Test === full);
      const runs = selected.filter(e => e.Action === 'run').length;
      const passes = selected.filter(e => e.Action === 'pass').length;
      const failures = selected.filter(e => e.Action === 'fail').length;
      assert.equal(runs, count, `${mutation}/${name}: missing runs`);
      assert.equal(passes + failures, count, `${mutation}/${name}: skipped or unfinished tests`);
      if (!mutation || name === 'sack') assert.equal(passes, count, r.stdout);
      if (targets[mutation]?.[0] === name) {
        assert.equal(failures, count, r.stdout);
        const evidence = selected.filter(e => targets[mutation][1].test(e.Output || ''));
        assert.equal(evidence.length, count, r.stdout);
        console.log(`EVIDENCE ${mutation}: ${evidence[0].Output.trim()}`);
      }
      console.log(`PROOF ${mutation || 'fixed'} ${name}: ran=${runs} passed=${passes} failed=${failures}`);
    }
  }
} finally {
  generate('');
}
