import assert from 'node:assert/strict';
import test from 'node:test';
import { execFileSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';
import { BaselineDefect, Report } from '../tests/windows/report.mjs';

test('default launch paths are stable when the routing script is called outside the repo', () => {
  const moduleURL = new URL('../tests/windows/launch.mjs', import.meta.url).href;
  const source = `import { launchOptions } from ${JSON.stringify(moduleURL)}; console.log(JSON.stringify(launchOptions()));`;
  const options = JSON.parse(execFileSync(process.execPath, ['--input-type=module', '-e', source], { cwd: tmpdir(), encoding: 'utf8', windowsHide: true }));
  assert.equal(options.entry, fileURLToPath(new URL('../server.mjs', import.meta.url)));
  assert.equal(options.engine, fileURLToPath(new URL('../engine/sing-box.exe', import.meta.url)));
});

test('both launcher flag spellings select Go and its exact engine without falling back to Node', () => {
  const moduleURL = new URL('../scripts/server-under-test.mjs', import.meta.url).href;
  const sharedURL = new URL('../tests/windows/launch.mjs', import.meta.url).href;
  const server = fileURLToPath(new URL('../bin/netswitch.exe', import.meta.url));
  const engine = fileURLToPath(new URL('../engine/selected.exe', import.meta.url));
  for (const [serverFlag, engineFlag] of [['--server-exe', '--engine-exe'], ['--server-executable', '--engine-executable']]) {
    const source = `process.argv.push(${JSON.stringify(serverFlag)}, ${JSON.stringify(server)}, ${JSON.stringify(engineFlag)}, ${JSON.stringify(engine)}); const { launchSpec } = await import(${JSON.stringify(moduleURL)}); const { serverCommand } = await import(${JSON.stringify(sharedURL)}); console.log(JSON.stringify({options:launchSpec, command:serverCommand(launchSpec,'data',{proxy:true})}));`;
    const { options, command } = JSON.parse(execFileSync(process.execPath, ['--input-type=module', '-e', source], { cwd: tmpdir(), encoding: 'utf8', windowsHide: true }));
    assert.equal(options.server, server);
    assert.equal(options.engine, engine);
    assert.equal(options.entry, null);
    assert.deepEqual(options.serverVersionArgs, ['--version']);
    assert.equal(command[0], server);
    assert(command[1].includes('--root'));
    assert(command[1].includes('--dev-proxy'));
    assert.deepEqual(command[1].slice(-2), ['--engine-executable', engine]);
    assert(!command[1].some((arg) => arg.endsWith('.mjs')));
  }
});

test('the Node e2e shim and an explicit production entry keep their distinct engine arguments', () => {
  const moduleURL = new URL('../scripts/server-under-test.mjs', import.meta.url).href;
  const sharedURL = new URL('../tests/windows/launch.mjs', import.meta.url).href;
  for (const entry of [null, fileURLToPath(new URL('../server.mjs', import.meta.url))]) {
    const source = `${entry ? `process.argv.push('--server-entry', ${JSON.stringify(entry)});` : ''} const { launchSpec } = await import(${JSON.stringify(moduleURL)}); const { serverCommand } = await import(${JSON.stringify(sharedURL)}); console.log(JSON.stringify({options:launchSpec, command:serverCommand(launchSpec,'data')}));`;
    const { options, command } = JSON.parse(execFileSync(process.execPath, ['--input-type=module', '-e', source], { cwd: tmpdir(), encoding: 'utf8', windowsHide: true }));
    assert.equal(command[1][0], options.entry);
    assert.equal(command[1].at(-2), entry ? '--engine-dir' : '--engine-executable');
  }
});

test('a disappearing baseline defect fails instead of silently changing the oracle', async () => {
  const report = new Report('baseline');
  await assert.rejects(report.test('cap hang', 'baseline-defect', async () => ({ ms: 1 })), /no longer reproduces/);
  assert.equal(report.results.length, 1);
  assert.equal(report.results[0].status, 'defect-not-reproduced');
  assert.deepEqual(report.results[0].evidence, { ms: 1 });
  const v1 = new Report('v1');
  await v1.test('cap hang', 'baseline-defect', async () => true);
  assert.equal(v1.results[0].status, 'pass');
});

test('pre-engine baselines are distinct from engine parity', async () => {
  const report = new Report('baseline');
  await report.test('native refusal', 'harness-baseline', async () => true);
  assert.equal(report.results[0].label, 'harness-baseline');
});

test('a baseline defect exemption cannot swallow a broken test or target', async () => {
  const report = new Report('baseline');
  await assert.rejects(report.test('unreachable baseline', 'baseline-defect', async () => { throw new Error('target down'); }), /target down/);
  assert.equal(report.results[0].status, 'fail');
});

test('confirmed baseline defects fail when the 1.0 profile is selected', async () => {
  const baseline = new Report('baseline');
  const defect = async () => { throw new BaselineDefect('port stalls', { elapsedMs: 60000 }); };
  await baseline.test('port reuse', 'baseline-defect', defect);
  assert.equal(baseline.results[0].status, 'confirmed-defect');
  const v1 = new Report('v1');
  await assert.rejects(v1.test('port reuse', 'baseline-defect', defect), /port stalls/);
});

test('parity cases cannot opt into baseline exemptions', async () => {
  const report = new Report('baseline');
  await assert.rejects(report.test('pin', 'parity', async () => { throw new BaselineDefect('wrong line'); }), /wrong line/);
  assert.equal(report.results[0].status, 'fail');
});
