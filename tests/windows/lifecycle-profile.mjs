import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { createWriteStream } from 'node:fs';
import { copyFile, mkdir, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { launchOptions, recordLaunch, startServer } from './launch.mjs';
import { lifecycleOutput, timedPhase } from './lifecycle.mjs';
import { targets } from './targets.mjs';
import { hostedOnly, run, startHarness, until } from './testisp/harness.mjs';

hostedOnly();
const native = launchOptions();
assert.equal(native.profile, 'v1');
const legacy = { ...native, profile: 'baseline', entry: path.resolve('server.mjs'), engine: path.resolve('engine/sing-box.exe') };
const directory = path.resolve('dist/windows-lifecycle');
await mkdir(directory, { recursive: true });
const log = createWriteStream(path.join(directory, 'server-output.log'));
const output = lifecycleOutput((chunk) => log.write(chunk));
const result = { architecture: process.arch, complete: false, variants: [] };
let harness, responder, active, client;
const calls = new Map();
let serial = 0;

const ask = (command, args = {}) => new Promise((resolve, reject) => {
  const id = ++serial;
  const timer = setTimeout(() => { calls.delete(id); reject(new Error(`${command}: profile client deadline`)); }, 20_000);
  calls.set(id, { resolve, reject, timer });
  client.send({ id, command, ...args });
});
const parseJSON = (text) => text.trim() ? JSON.parse(text.replace(/^\uFEFF/, '')) : [];
async function inspectStopped(phases) {
  const state = await timedPhase(phases, 'harnessNetworkCheckMs', async () =>
    parseJSON((await run('powershell.exe', ['-NoProfile', '-File', path.resolve('scripts/tun-test-network.ps1'), '-Action', 'state'])).stdout));
  assert(Object.values(state).every((items) => items.length === 0), JSON.stringify(state));
  const value = await timedPhase(phases, 'harnessPnPCheckMs', async () =>
    parseJSON((await run('powershell.exe', ['-NoProfile', '-File', path.resolve('tests/windows/pnp.ps1')])).stdout));
  const pnp = Array.isArray(value) ? value : value ? [value] : [];
  assert(!pnp.some((device) => device.present), 'A present NetSwitch adapter survived routing off');
  return { state, pnp }; // A legacy phantom is recorded, not credited to 1.0 cleanup.
}

try {
  harness = await startHarness(path.join(directory, 'testisp'));
  responder = await targets(harness.uplink.address);
  await harness.control('targets', { ports: [responder.direct.http, ...responder.direct.udp] });
  const clientExe = path.join(directory, 'lifecycle-app.exe');
  await copyFile(process.execPath, clientExe);
  client = spawn(clientExe, [path.resolve('tests/windows/client.mjs')], { windowsHide: true, stdio: ['ignore', 'inherit', 'inherit', 'ipc'] });
  client.on('message', ({ id, result, error }) => {
    const pending = calls.get(id);
    if (!pending) return;
    calls.delete(id); clearTimeout(pending.timer);
    if (error) pending.reject(new Error(error)); else pending.resolve(result);
  });
  client.on('exit', () => {
    for (const pending of calls.values()) { clearTimeout(pending.timer); pending.reject(new Error('Profile client exited')); }
    calls.clear();
  });
  // The legacy engine leaves a non-present adapter after stop. Measure 1.0
  // first so that its intentional refusal to adopt a foreign adapter cannot
  // turn the legacy cleanup defect into a failed 1.0 startup precondition.
  for (const [name, options] of [['1.0', native], ['0.3.x', legacy]]) {
    const data = path.join(directory, name);
    await mkdir(data, { recursive: true });
    await writeFile(path.join(data, 'settings.json'), JSON.stringify({ checkForUpdates: false }));
    const variant = { name, executables: await recordLaunch(options), setup: {}, phases: {} };
    result.variants.push(variant);
    const nativeStart = output.events.length;
    active = await timedPhase(variant.setup, 'controllerLaunchMs', () => startServer(options, data, output));
    await timedPhase(variant.setup, 'initialRoutingReadyMs', () => active.on());
    await active.api('lines/add', { alias: 'TestISP' });
    const state = await active.on();
    const second = state.lines.find((line) => line.alias === 'TestISP');
    assert(second, 'TestISP was not discovered');
    await active.api('app-line', { path: clientExe, line: second.id });
    await active.api('routing', { on: false });
    await until(async () => (await active.api('state')).routing.status === 'off', 'profile begins with routing off');
    await inspectStopped(variant.setup);
    const started = performance.now();
    const eventStart = output.events.length;
    await timedPhase(variant.phases, 'routingOnCommandMs', () => active.api('routing', { on: true }));
    await timedPhase(variant.phases, 'routingOnReadyMs', () => active.on());
    const before = await timedPhase(variant.phases, 'harnessBeforeFlowStatsMs', () => harness.control('stats'));
    variant.flow = await timedPhase(variant.phases, 'firstSuccessfulFlowMs', () => ask('open', { target: responder.virtual }));
    await timedPhase(variant.phases, 'clientCloseMs', () => ask('close'));
    const after = await timedPhase(variant.phases, 'harnessAfterFlowStatsMs', () => harness.control('stats'));
    assert(after.testisp.connections > before.testisp.connections, 'First flow did not cross TestISP');
    if (name === '1.0') {
      variant.runningEngine = await timedPhase(variant.phases, 'harnessEngineStatsMs', () => active.api('engine-command', { method: 'stats' }));
    }
    await timedPhase(variant.phases, 'routingOffCommandMs', () => active.api('routing', { on: false }));
    await timedPhase(variant.phases, 'routingOffReadyMs', () =>
      until(async () => (await active.api('state')).routing.status === 'off', 'routing off and engine stopped'));
    variant.stopped = await inspectStopped(variant.phases);
    variant.totalMs = performance.now() - started;
    variant.nativeCycle = output.events.slice(eventStart);
    variant.nativeIncludingSetup = output.events.slice(nativeStart);
    console.log(`WINDOWS LIFECYCLE COMPARISON ${JSON.stringify(variant)}`);
    await active.quit();
    active = undefined;
    await writeFile(path.join(directory, 'report.json'), JSON.stringify(result, null, 2));
  }
  result.complete = true;
} catch (error) {
  result.error = error.stack;
  console.error(error);
  process.exitCode = 1;
} finally {
  if (active) await active.quit().catch((error) => { result.quitError = error.stack; process.exitCode = 1; });
  if (client?.connected) client.disconnect();
  if (responder) await responder.close();
  if (harness) await harness.close().catch((error) => { result.cleanupError = error.stack; process.exitCode = 1; });
  await writeFile(path.join(directory, 'report.json'), JSON.stringify(result, null, 2));
  log.end();
}
