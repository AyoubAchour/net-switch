import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { createWriteStream } from 'node:fs';
import { copyFile, mkdir, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { launchOptions, recordLaunch, startServer } from './launch.mjs';
import { lifecycleOutput, timedPhase } from './lifecycle.mjs';
import { startInspection } from './inspection.mjs';
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
let harness, responder, active, client, inspection;
const calls = new Map();
let serial = 0;
const priorAdapterFirst = process.env.NETSWITCH_ENGINE_ADAPTER_FIRST;

const ask = (command, args = {}) => new Promise((resolve, reject) => {
  const id = ++serial;
  const timer = setTimeout(() => { calls.delete(id); reject(new Error(`${command}: profile client deadline`)); }, 20_000);
  calls.set(id, { resolve, reject, timer });
  client.send({ id, command, ...args });
});
const parseJSON = (text) => text.trim() ? JSON.parse(text.replace(/^\uFEFF/, '')) : [];
async function inspectState(phases, running = false) {
  const key = (name) => running ? `running${name[0].toUpperCase()}${name.slice(1)}` : name;
  const standaloneState = await timedPhase(phases, key('standaloneNetworkCheckMs'), async () =>
    parseJSON((await run('powershell.exe', ['-NoProfile', '-File', path.resolve('scripts/tun-test-network.ps1'), '-Action', 'state'])).stdout));
  const state = await timedPhase(phases, key('harnessNetworkCheckMs'), () => inspection.query('network'));
  assert.deepEqual(state, standaloneState, 'Reused inspection disagrees with the unchanged standalone network script');
  if (running) assert(state.adapters.length > 0 && state.routes.length > 0, 'Running inspection did not see the adapter and routes');
  else assert(Object.values(state).every((items) => items.length === 0), JSON.stringify(state));
  const standalonePnP = await timedPhase(phases, key('standalonePnPCheckMs'), async () =>
    parseJSON((await run('powershell.exe', ['-NoProfile', '-File', path.resolve('tests/windows/pnp.ps1')])).stdout));
  const value = await timedPhase(phases, key('harnessPnPCheckMs'), () => inspection.query('pnp'));
  assert.deepEqual(value, standalonePnP, 'Reused inspection disagrees with the unchanged standalone PnP script');
  const pnp = Array.isArray(value) ? value : value ? [value] : [];
  assert.equal(pnp.some((device) => device.present), running, 'PnP inspection did not follow the routing transition');
  return { state, pnp }; // A legacy phantom is recorded, not credited to 1.0 cleanup.
}

try {
  inspection = await startInspection();
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
  const variants = [['1.0', native, false]];
  if (process.argv.includes('--adapter-first-comparison')) variants.push(['1.0-adapter-first', native, true]);
  variants.push(['0.3.x', legacy, false]);
  for (const [name, options, adapterFirst] of variants) {
    const isNative = options.profile === 'v1';
    process.env.NETSWITCH_ENGINE_ADAPTER_FIRST = adapterFirst ? '1' : '0';
    const data = path.join(directory, name);
    await mkdir(data, { recursive: true });
    await writeFile(path.join(data, 'settings.json'), JSON.stringify({ checkForUpdates: false }));
    const variant = { name, executables: await recordLaunch(options), setup: {}, phases: {},
      nativeStopProfiled: isNative && process.env.NETSWITCH_ENGINE_STOP_TRACE === '1',
      nativeCloseAfterRoutes: isNative && process.env.NETSWITCH_ENGINE_CLOSE_AFTER_ROUTES === '1',
      nativeAdapterFirst: adapterFirst };
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
    await inspectState(variant.setup);
    const started = performance.now();
    const eventStart = output.events.length;
    await timedPhase(variant.phases, 'routingOnCommandMs', () => active.api('routing', { on: true }));
    await timedPhase(variant.phases, 'routingOnReadyMs', () => active.on());
    const before = await timedPhase(variant.phases, 'harnessBeforeFlowStatsMs', () => harness.control('stats'));
    variant.flow = await timedPhase(variant.phases, 'firstSuccessfulFlowMs', () => ask('open', { target: responder.virtual }));
    await timedPhase(variant.phases, 'clientCloseMs', () => ask('close'));
    const after = await timedPhase(variant.phases, 'harnessAfterFlowStatsMs', () => harness.control('stats'));
    assert(after.testisp.connections > before.testisp.connections, 'First flow did not cross TestISP');
    if (isNative) {
      variant.runningEngine = await timedPhase(variant.phases, 'harnessEngineStatsMs', () => active.api('engine-command', { method: 'stats' }));
    }
    variant.runningInspection = await inspectState(variant.phases, true);
    await timedPhase(variant.phases, 'routingOffCommandMs', () => active.api('routing', { on: false }));
    await timedPhase(variant.phases, 'routingOffReadyMs', () =>
      until(async () => (await active.api('state')).routing.status === 'off', 'routing off and engine stopped'));
    variant.stopped = await inspectState(variant.phases);
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
  if (inspection) await inspection.close().catch((error) => { result.inspectionError = error.stack; process.exitCode = 1; });
  await writeFile(path.join(directory, 'report.json'), JSON.stringify(result, null, 2));
  log.end();
  if (priorAdapterFirst === undefined) delete process.env.NETSWITCH_ENGINE_ADAPTER_FIRST;
  else process.env.NETSWITCH_ENGINE_ADAPTER_FIRST = priorAdapterFirst;
}
