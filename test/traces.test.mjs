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
  const provenance = JSON.parse(await readFile(new URL('../tests/oracle/provenance.json', import.meta.url), 'utf8'));
  assert.deepEqual(Object.keys(provenance.fixtures).sort(), Object.keys(actual).sort());
  assert.deepEqual(Object.keys(actual).sort(), names.map((name) => name.replace('.trace.json', '')).sort());
  for (const name of names) {
    const expected = JSON.parse(await readFile(new URL(name, dir), 'utf8'));
    const trace = actual[expected.name];
    const source = provenance.fixtures[expected.name];
    assert.equal(createHash('sha256').update(await readFile(new URL(name, dir))).digest('hex'), source.sha256, `${name}: frozen bytes changed`);
    assert.equal(trace.baseline, source.baseline);
    assert.deepEqual(trace.hooks, source.hooks);
    assert.deepEqual(trace.scenario, expected.scenario, `${name}: input scenario changed`);
    assert.equal(trace.entries.length, expected.entries.length, `${name}: entry count`);
    for (let index = 0; index < expected.entries.length; index++) {
      assert.deepEqual(orderedPolicy(trace.entries[index]), orderedPolicy(expected.entries[index]), `${name}: first mismatch at sequence ${index}`);
    }
  }
  t.diagnostic(`Compared ${names.length} traces, ${Object.values(actual).reduce((count, trace) => count + trace.entries.length, 0)} entries.`);
});

test('the recorded scenarios exercise every HTTP route and restored log condition', async (t) => {
  const directory = new URL('../tests/oracle/fixtures/', import.meta.url);
  const traces = await Promise.all((await readdir(directory)).filter((name) => name.endsWith('.trace.json')).map(async (name) => JSON.parse(await readFile(new URL(name, directory), 'utf8'))));
  const httpSource = await readFile(new URL('../internal/control/http.go', import.meta.url), 'utf8');
  const registered = [...new Set([...httpSource.matchAll(/"(\/api\/[a-z][a-z/-]*)"/g)].map((match) => match[1]))].sort();
  const nodeSource = await readFile(new URL('../lib/server-factory.mjs', import.meta.url), 'utf8');
  const nodeRoutes = [...new Set([...nodeSource.matchAll(/'(?:GET|POST) (\/api\/[a-z][a-z/-]*)'/g)].map((match) => match[1]).concat([...nodeSource.matchAll(/url\.pathname === '(\/api\/icon)'/g)].map((match) => match[1])))].sort();
  assert.deepEqual(registered, nodeRoutes, 'Node and Go route lists diverged');
  const exercised = [...new Set(traces.flatMap((trace) => trace.scenario.steps.filter((step) => step.kind === 'http').map((step) => step.route.split('?')[0])))].sort();
  assert.deepEqual(exercised, registered);
  assert.deepEqual(exercised, nodeRoutes);
  const logs = traces.flatMap((trace) => trace.entries.filter((entry) => entry.kind === 'log').map((entry) => entry.value.text));
  for (const condition of [/hasn't answered for 20 polls; restarting it/, /^routing restarts to use /, /'s data cap reset$/, /^added /, /^removed /, /^line order: /, /^starting with Windows is on$/, /^starting with Windows is off$/, /^quit failed:/]) assert(logs.some((line) => condition.test(line)), `unexercised log: ${condition}`);
  t.diagnostic(`${registered.length} HTTP endpoints and all nine requested log conditions exercised.`);
});

test('Undo failures and partial restoration still match the Node oracle', async (t) => {
  const result = spawnSync(process.execPath, ['--experimental-vm-modules', '--disable-warning=ExperimentalWarning', 'tests/oracle/undo.mjs'], {
    cwd: new URL('../', import.meta.url), encoding: 'utf8', timeout: 30_000, windowsHide: true,
  });
  assert.equal(result.status, 0, result.stderr);
  const actual = JSON.parse(result.stdout);
  const expected = JSON.parse(await readFile(new URL('../tests/oracle/fixtures/undo.json', import.meta.url), 'utf8'));
  assert.deepEqual(actual, expected);
  assert.equal(actual.length, 6);
  t.diagnostic('Six Undo oracle cases: damaged policy/metrics, policy/save failures, ordered partial restore, empty record.');
});

test('policy comparison rejects reordered pins and shares', () => {
  for (const key of ['appLines', 'shares']) {
    assert.notDeepEqual(orderedPolicy({ [key]: { b: 1, a: 2 } }), orderedPolicy({ [key]: { a: 2, b: 1 } }));
  }
});
