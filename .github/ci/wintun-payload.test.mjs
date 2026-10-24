import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import { readWorkflow, jobRuns } from './workflows.mjs';

const text = readFileSync(new URL('../workflows/ci.yml', import.meta.url), 'utf8');
const { jobs } = readWorkflow(text);

test('payload pilot dispatch selects only the fixed three-runner job', () => {
  const context = {
    github: { event_name: 'workflow_dispatch' },
    inputs: { regular_jobs: false, control_security: false, wintun_integrity: true, wintun_integrity_scenario: 'payload' },
    needs: { changes: { result: 'skipped', outputs: {} } },
    functions: { cancelled: () => false, success: () => true, always: () => true },
  };
  assert.deepEqual([...jobs].filter(([, job]) => jobRuns(job, context)).map(([name]) => name), ['wintun-payload-pilot']);
  const pilot = text.split('  wintun-payload-pilot:\n')[1].split('\n  wintun-integrity:')[0];
  assert.equal((pilot.match(/runner: windows-latest/g) ?? []).length, 2);
  assert.equal((pilot.match(/runner: windows-11-arm/g) ?? []).length, 1);
  assert.match(pilot, /max-parallel: 3/);
  assert.doesNotMatch(pilot, /continue-on-error|wintun_integrity_shards/);
  const steps = jobs.get('wintun-payload-pilot').steps;
  assert.ok(steps.some(s => s.run?.includes('TestPayloadWords')));
  assert.ok(steps.some(s => s.run?.includes('TestWintunCaptureProof')));
});
