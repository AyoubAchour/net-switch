import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { readFile } from 'node:fs/promises';
import { test } from 'node:test';

test('server matches the frozen pre-refactor Node oracle', async () => {
  const fixture = JSON.parse(await readFile(new URL('../tests/oracle/fixtures/node.json', import.meta.url), 'utf8'));
  const run = spawnSync(process.execPath, ['--experimental-vm-modules', '--disable-warning=ExperimentalWarning', 'tests/oracle/record.mjs'], {
    cwd: new URL('../', import.meta.url), encoding: 'utf8', maxBuffer: 16 * 1024 * 1024, timeout: 60_000, env: { ...process.env, TZ: 'UTC' }, windowsHide: true,
  });
  assert.equal(run.status, 0, run.stderr);
  assert.deepEqual(JSON.parse(run.stdout), fixture);
  const source = await readFile(new URL('../server.mjs', import.meta.url), 'utf8');
  const routes = [...source.matchAll(/'(GET|POST) (\/api\/[^']+)':/g)].map((match) => `${match[1]} ${match[2]}`);
  for (const route of routes) assert.ok(fixture.routes.some((entry) => `${entry.method} ${entry.route}` === route), `Unrecorded route: ${route}`);
  for (const name of ['settings.json', 'settings.json.bak', 'usage.json', 'windows-undo.json', 'windows-undo.json.bak', 'engine-config.json']) {
    assert.ok(fixture.effects.some((entry) => entry.kind === 'write' && entry.file.endsWith(`/${name}`)), `Missing write: ${name}`);
  }
  assert.ok(fixture.effects.some((entry) => entry.kind === 'engine' && entry.method === 'PUT'));
  assert.ok(fixture.effects.some((entry) => entry.kind === 'engine' && entry.method === 'DELETE'));
});
