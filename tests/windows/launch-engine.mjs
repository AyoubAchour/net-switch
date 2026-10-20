import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { until } from './testisp/harness.mjs';

export async function startEngineDriver(options, dataDir, output) {
  assert(options.entry?.endsWith('engine-driver.mjs'), 'v1 requires the explicit real-engine harness controller');
  const child = spawn(options.server, [options.entry, options.engine, dataDir], {
    windowsHide: true, stdio: ['ignore', 'pipe', 'pipe', 'ipc'],
  });
  child.stdout.on('data', output); child.stderr.on('data', output);
  let serial = 0, ready = false, spawnError;
  const pending = new Map();
  child.on('error', (error) => { spawnError = error; });
  child.on('message', (message) => {
    if (message.ready) { ready = true; return; }
    const item = pending.get(message.id);
    if (!item) return;
    pending.delete(message.id); clearTimeout(item.timer);
    if (message.error) item.reject(new Error(message.error)); else item.resolve(message.result);
  });
  child.on('exit', () => {
    for (const item of pending.values()) { clearTimeout(item.timer); item.reject(new Error('Harness controller exited')); }
    pending.clear();
  });
  await until(() => {
    if (spawnError) throw spawnError;
    assert(child.exitCode === null && child.signalCode === null, `Harness controller exited ${child.exitCode ?? child.signalCode}`);
    return ready;
  }, 'authenticated real engine and harness controller', 90_000);
  const api = (route, body) => new Promise((resolve, reject) => {
    const id = ++serial;
    const timer = setTimeout(() => { pending.delete(id); reject(new Error(`Harness action timed out: ${route}`)); }, 90_000);
    pending.set(id, { resolve, reject, timer });
    child.send({ id, route, body });
  });
  const on = () => until(async () => {
    assert(child.exitCode === null && child.signalCode === null, 'Harness controller died');
    const state = await api('state');
    return state.routing.status === 'on' && state;
  }, 'real-engine routing on', 120_000);
  const quit = async () => {
    if (child.exitCode !== null || child.signalCode !== null) return;
    await api('quit', {});
    await until(() => child.exitCode !== null || child.signalCode !== null, 'harness controller quit', 30_000);
    assert.equal(child.exitCode, 0);
  };
  return { child, api, on, quit };
}
