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
  const second = await run.start();
  await firstHooks.settings.update({ checkForUpdates: false });
  assert.equal(first.buildState().settings.checkForUpdates, false);
  assert.equal(second.buildState().settings.checkForUpdates, true);
  await first.shutdown();
  assert.equal(first.buildState().routing.status, 'off');
  assert.equal(second.buildState().routing.status, 'on');
});

test('a failed settings write leaves the API behind neither disk nor engine', async () => {
  const run = await oracle({ initial: { lines } });
  const hooks = run.server.oracleHooks;
  const before = JSON.stringify(hooks.settings.values);
  const previous = hooks.settings.io.fs.rename;
  hooks.settings.io.fs.rename = async (from, to) => {
    if (to.endsWith('/settings.json')) throw new Error('injected write failure');
    return previous(from, to);
  };
  const response = await run.request('POST', '/api/app-line', { path: 'C:\\Apps\\Firefox.exe', line: 'b2' });
  assert.equal(response.status, 500);
  assert.equal(JSON.stringify(hooks.settings.values), before);
  assert.deepEqual(JSON.parse(JSON.stringify(hooks.engine.appLines)), {});
  assert.ok(run.outputs.some((entry) => entry.kind === 'log' && entry.text.includes('injected write failure')));
});
