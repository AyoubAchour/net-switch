import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { test } from 'node:test';
import { evaluate, readWorkflow } from './workflows.mjs';

const workflowText = readFileSync(new URL('../workflows/ci.yml', import.meta.url), 'utf8');
const normal = readWorkflow(workflowText).jobs.get('wintun');
const phases = JSON.parse(readFileSync(new URL('../../scripts/wintun-integrity-sequence.json', import.meta.url), 'utf8'));
const runner = fileURLToPath(new URL('../../scripts/test-wintun-integrity.ps1', import.meta.url));

function assertParity(plan) {
  for (const phase of plan) {
    // Start-Process's argument joining is safe only while these manifest
    // arguments have no whitespace. Fail before dispatch if that changes.
    assert.ok(phase.args.every(arg => !/\s/.test(arg)), phase.name);
    assert.ok(phase.timeoutSeconds > 0 && phase.timeoutSeconds <= 1200);
  }
  const expected = normal.steps.flatMap(step => {
    const selectors = [...(step.run ?? '').matchAll(/'-test.run=([^']+)'/g)].map(match => match[1]);
    // The normal profile step invokes this selector twice in its mode loop.
    return step.run?.includes("foreach ($mode in @('dll', 'ours'))") ? selectors.concat(selectors) : selectors;
  });
  const actual = plan.filter(phase => phase.kind === 'test').map(phase => {
    assert.equal(phase.args.filter(arg => arg.startsWith('-test.run=')).length, 1);
    return phase.args.find(arg => arg.startsWith('-test.run=')).slice(10);
  });
  assert.deepEqual(actual, expected, 'all normal native test invocations stay in their original order');
  assert.deepEqual(plan.filter(phase => phase.diagnostic).map(phase => phase.name), ['performance-dll', 'performance-inprocess']);
  const fuzz = plan.find(phase => phase.name === 'fuzz');
  assert.equal(fuzz.ci, '0');
  assert.ok(normal.steps.some(step => step.run?.replaceAll("'", '').includes(`go ${fuzz.args.join(' ')}`)));
  for (const mode of ['dll', 'ours']) {
    const pprof = plan.find(phase => phase.name === `pprof-${mode}`);
    assert.ok(normal.steps.some(step => step.run?.replaceAll('$mode', mode).replaceAll('"', '').includes(`go ${pprof.args.join(' ')}`)));
    assert.equal(pprof.requiresSuccess, `profile-${mode}`);
    assert.equal(plan.find(phase => phase.name === `profile-${mode}`).diagnostic, undefined, 'profiling retains its original payload and 24 transfers');
  }
  assert.equal(plan.find(phase => phase.name === 'race-recovery').arch, 'x64');
  assert.equal(plan.find(phase => phase.name === 'profile-ours').requiresSuccess, 'pprof-dll');
  assert.deepEqual(plan.filter(phase => !phase.runAfterFailure).map(phase => phase.name), ['ring-recovery', 'registrar']);
}

test('full diagnostic preserves the normal Wintun sequence, including its post-performance phases', () => assertParity(phases));

test('the sequence guard rejects omitted or reordered state-producing phases', () => {
  assert.throws(() => assertParity(phases.filter(phase => phase.name !== 'registrar')));
  const reordered = structuredClone(phases);
  [reordered[0], reordered[3]] = [reordered[3], reordered[0]];
  assert.throws(() => assertParity(reordered));
});

test('20 independent shards are selected per architecture without fail-fast cancellation', () => {
  const expr = /shard: \$\{\{ fromJSON\((.*)\) \}\}/.exec(workflowText)?.[1];
  assert.ok(expr, 'shard expression');
  for (const count of [1, 5, 20]) {
    const shards = JSON.parse(evaluate(expr, { inputs: { wintun_integrity_shards: String(count) } }));
    assert.deepEqual(shards, Array.from({length:count}, (_, i) => i+1));
  }
  assert.match(workflowText, /strategy: &wintun-integrity-strategy\s+fail-fast: false\s+max-parallel: 20/);
  assert.match(workflowText, /wintun-integrity-arm64:[\s\S]*?strategy: \*wintun-integrity-strategy/);
});

for (const arch of ['x64', 'arm64']) {
  for (const scenario of ['isolated', 'full']) {
    test(`PowerShell plan is read-only: ${scenario}/${arch}`, { skip: process.platform !== 'win32' }, () => {
      // No nested test runner, engine binary, network, adapter or fixture.
      const output = execFileSync('pwsh.exe', ['-NoProfile', '-File', runner, '-PlanOnly', '-Scenario', scenario, '-Arch', arch], {
        encoding:'utf8', windowsHide:true, timeout:15000,
        env:{...process.env, GITHUB_ACTIONS:'false', NETSWITCH_WINTUN_CI:'0', NETSWITCH_WINTUN_INTEGRITY:'0'},
      });
      const plan = JSON.parse(output);
      assert.equal(plan.arch, arch);
      assert.equal(plan.scenario, scenario);
      if (scenario === 'isolated') {
        assert.equal(plan.focus, 'tcp_8_MBps');
        assert.deepEqual(plan.phases.map(phase => phase.name), ['performance-dll']);
        assert.equal(plan.phases[0].timeoutSeconds, 480);
      } else {
        assert.equal(plan.focus, '', 'all five metrics run on each pair adapter');
        assert.deepEqual(plan.phases.map(phase => phase.name), phases.filter(phase => !phase.arch || phase.arch === arch).map(phase => phase.name));
      }
    });
  }
}
