import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { test } from 'node:test';

test('server factory isolation and failed-write rollback', (t) => {
  const env = { ...process.env };
  delete env.NODE_TEST_CONTEXT;
  const result = spawnSync(process.execPath, ['--experimental-vm-modules', '--disable-warning=ExperimentalWarning', '--test-reporter=tap', 'tests/oracle/factory-tests.mjs'], {
    cwd: new URL('../', import.meta.url), encoding: 'utf8', timeout: 60_000, windowsHide: true,
    env,
  });
  assert.equal(result.status, 0, result.stdout + result.stderr);
  assert.doesNotMatch(result.stdout + result.stderr, /recursively|skipping running files/);
  assert.match(result.stdout, /# tests 5\b/);
  assert.match(result.stdout, /# pass 5\b/);
  assert.match(result.stdout, /# fail 0\b/);
  t.diagnostic(result.stdout);
});
