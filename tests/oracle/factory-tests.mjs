import assert from 'node:assert/strict';
import { test } from 'node:test';
import { oracle } from './harness.mjs';
import { lines } from './record.mjs';

test('importing the server does not listen, start workers or write files', async () => {
  const run = await oracle({ importOnly: true });
  assert.deepEqual(run.outputs, []);
  assert.equal(typeof run.server.createServer, 'function');
});

test('each factory owns its settings, routing state and queues', async () => {
  const run = await oracle({ importOnly: true, initial: { lines } });
  const first = await run.start();
  const firstHooks = run.server.oracleHooks;
  run.files.set('/oracle/second/settings.json', JSON.stringify({ lines }));
  const second = await run.start({ process: { ...run.process, argv: ['node', '/oracle/server.mjs', '--user-data', '/oracle/second', '--machine-data', '/oracle/second'] } });
  await firstHooks.settings.update({ checkForUpdates: false });
  assert.equal(first.buildState().settings.checkForUpdates, false);
  assert.equal(second.buildState().settings.checkForUpdates, true);
  await first.shutdown();
  assert.equal(first.buildState().routing.status, 'off');
  assert.equal(second.buildState().routing.status, 'on');
});

test('a failed settings write leaves the API behind neither disk nor engine', async () => {
  const run = await oracle({ importOnly: true, initial: { lines } });
  let fail = false;
  await run.start({ fs: { ...run.fs, rename: async (from, to) => {
    if (fail && to.endsWith('/settings.json')) throw new Error('injected write failure');
    return run.fs.rename(from, to);
  } } });
  const hooks = run.server.oracleHooks;
  const before = JSON.stringify(hooks.settings.values);
  fail = true;
  const response = await run.request('POST', '/api/app-line', { path: 'C:\\Apps\\Firefox.exe', line: 'b2' });
  assert.equal(response.status, 500);
  assert.equal(JSON.stringify(hooks.settings.values), before);
  assert.deepEqual(JSON.parse(JSON.stringify(hooks.engine.appLines)), {});
  assert.ok(run.outputs.some((entry) => entry.kind === 'log' && entry.text.includes('injected write failure')));
});

test('the entry starts once when argv uses a junction spelling', async () => {
  const run = await oracle({ argvEntry: '/junction/server.mjs' });
  assert.equal(run.outputs.filter((entry) => entry.kind === 'console' && entry.text.includes('Net Switch is running')).length, 1);
  assert.ok(run.files.has('/oracle/data/server.json'));
});

test('engine, updates and helper options are used by startup and shutdown', async () => {
  const run = await oracle({ importOnly: true, initial: { lines } });
  const calls = [];
  const engine = new run.Engine({ platform: run.platform, singBoxPath: '/oracle/engine/sing-box.exe', dataDir: '/oracle/data', mode: 'tun' });
  const updates = { offer: null, start() { calls.push('updates start'); }, stop() { calls.push('updates stop'); } };
  class Monitor extends run.helper.LineMonitor {
    start() { calls.push('monitor start'); }
    stop() { calls.push('monitor stop'); }
  }
  const instance = await run.start({ engine, updates, helper: { LineMonitor: Monitor, findHelper: () => { calls.push('find helper'); return null; } } });
  assert.equal(run.server.oracleHooks.engine, engine);
  assert.equal(engine.status, 'on');
  await instance.shutdown();
  assert.equal(engine.status, 'off');
  for (const call of ['find helper', 'updates start', 'monitor start', 'monitor stop']) assert.ok(calls.includes(call), call);
});
