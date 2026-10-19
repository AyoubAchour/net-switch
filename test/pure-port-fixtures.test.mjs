import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { readFile } from 'node:fs/promises';
import { test } from 'node:test';
import { orderedPolicy } from '../tests/oracle/ordered.mjs';

test('Go test vectors keep the original Node test names and public calls', async () => {
  const result = spawnSync(process.execPath, ['--experimental-vm-modules', '--disable-warning=ExperimentalWarning', 'tests/oracle/record-pure-tests.mjs'], {
    cwd: new URL('../', import.meta.url), encoding: 'utf8', timeout: 60_000, maxBuffer: 16 * 1024 * 1024, env: { ...process.env, TZ: 'UTC' }, windowsHide: true,
  });
  assert.equal(result.status, 0, result.stderr);
  for (const [name, cases] of Object.entries(JSON.parse(result.stdout))) {
    const fixture = JSON.parse(await readFile(new URL(`../internal/${name}/node-tests.json`, import.meta.url), 'utf8'));
    assert.deepEqual(orderedPolicy(cases), orderedPolicy(fixture), `${name}: original tests changed; port the changed assertions too`);
  }
});

test('Go usage vectors retain the Node timezone and gap behavior', async () => {
  const result = spawnSync(process.execPath, ['tests/oracle/usage-zones.mjs'], {
    cwd: new URL('../', import.meta.url), encoding: 'utf8', timeout: 60_000, windowsHide: true,
  });
  assert.equal(result.status, 0, result.stderr);
  const fixture = JSON.parse(await readFile(new URL('../internal/usage/node-zones.json', import.meta.url), 'utf8'));
  assert.deepEqual(JSON.parse(result.stdout), fixture);
});
