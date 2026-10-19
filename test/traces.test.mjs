import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { readFile, readdir } from 'node:fs/promises';
import { test } from 'node:test';
import { orderedPolicy } from '../tests/oracle/ordered.mjs';

test('recorded controller traces replay in the same input and completion order', async (t) => {
  t.diagnostic(`Node ${process.version}, ${process.execPath}, SHA-256 ${createHash('sha256').update(await readFile(process.execPath)).digest('hex')}`);
  const result = spawnSync(process.execPath, ['--experimental-vm-modules', '--disable-warning=ExperimentalWarning', 'tests/oracle/traces.mjs'], {
    cwd: new URL('../', import.meta.url), encoding: 'utf8', maxBuffer: 16 * 1024 * 1024, timeout: 60_000, env: { ...process.env, TZ: 'UTC' }, windowsHide: true,
  });
  assert.equal(result.status, 0, result.stderr);
  const actual = JSON.parse(result.stdout);
  const dir = new URL('../tests/oracle/fixtures/', import.meta.url);
  const names = (await readdir(dir)).filter((name) => name.endsWith('.trace.json'));
  assert.deepEqual(Object.keys(actual).sort(), names.map((name) => name.replace('.trace.json', '')).sort());
  for (const name of names) {
    const expected = JSON.parse(await readFile(new URL(name, dir), 'utf8'));
    const trace = actual[expected.name];
    assert.deepEqual(trace.scenario, expected.scenario, `${name}: input scenario changed`);
    assert.equal(trace.entries.length, expected.entries.length, `${name}: entry count`);
    for (let index = 0; index < expected.entries.length; index++) {
      assert.deepEqual(orderedPolicy(trace.entries[index]), orderedPolicy(expected.entries[index]), `${name}: first mismatch at sequence ${index}`);
    }
  }
});

test('policy comparison rejects reordered pins and shares', () => {
  for (const key of ['appLines', 'shares']) {
    assert.notDeepEqual(orderedPolicy({ [key]: { b: 1, a: 2 } }), orderedPolicy({ [key]: { a: 2, b: 1 } }));
  }
});
