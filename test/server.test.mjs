import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { test } from 'node:test';

test('server factory isolation and failed-write rollback', () => {
  const result = spawnSync(process.execPath, ['--experimental-vm-modules', '--disable-warning=ExperimentalWarning', '--test', 'tests/oracle/factory-tests.mjs'], {
    cwd: new URL('../', import.meta.url), encoding: 'utf8', timeout: 60_000, windowsHide: true,
  });
  assert.equal(result.status, 0, result.stdout + result.stderr);
});
