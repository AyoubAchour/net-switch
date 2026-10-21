import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { until } from './testisp/harness.mjs';

export async function startEngineDriver(options, dataDir, output) {
  assert(options.entry?.endsWith('engine-driver.mjs'), 'v1 requires the explicit real-engine harness controller');
  const child = spawn(options.server, [options.entry, options.engine, dataDir], {
    windowsHide: true, stdio: ['ignore', 'pipe', 'pipe', 'ipc'],
  });
  let tail = '';
  const capture = (chunk) => { tail = (tail + chunk.toString()).slice(-8192); output(chunk); };
  child.stdout.on('data', capture); child.stderr.on('data', capture);
  let serial = 0, resolveReady, rejectReady;
  const started = new Promise((resolve, reject) => { resolveReady = resolve; rejectReady = reject; });
  const exited = () => new Error(`Harness controller exited ${child.exitCode ?? child.signalCode}\n${tail}`);
  const startupTimer = setTimeout(() => rejectReady(new Error(`Authenticated engine/controller startup deadline\n${tail}`)), 90_000);
  const pending = new Map();
  child.on('error', rejectReady);
  child.on('message', (message) => {
    if (message.ready) { resolveReady(); return; }
    const item = pending.get(message.id);
    if (!item) return;
    pending.delete(message.id); clearTimeout(item.timer);
    if (message.error) item.reject(new Error(message.error)); else item.resolve(message.result);
  });
  child.on('exit', () => {
    rejectReady(exited());
    for (const item of pending.values()) { clearTimeout(item.timer); item.reject(exited()); }
    pending.clear();
  });
  // A dead controller cannot become ready. Preserve its native error and stop
  // immediately instead of letting the generic transient-condition poller
  // swallow the exit for another 90 seconds.
  try { await started; }
  catch (error) { child.kill(); throw error; }
  finally { clearTimeout(startupTimer); }
  const api = (route, body) => new Promise((resolve, reject) => {
    const id = ++serial;
    const timer = setTimeout(() => { pending.delete(id); reject(new Error(`Harness action timed out: ${route}`)); }, 90_000);
    pending.set(id, { resolve, reject, timer });
    child.send({ id, route, body });
  });
  const on = () => until(async () => {
    assert(child.exitCode === null && child.signalCode === null, 'Harness controller died');
    const state = await api('state');
    if (state.routing.status === 'error') throw new Error(state.routing.error);
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
