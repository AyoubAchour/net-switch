// NEVER run this on a developer's PC. It changes routes and briefly changes DNS.
// The guard also excludes self-hosted runners. The engine-config job explicitly
// uses --engine-adapter; the default tests selected Control. Both use local TLS.
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { copyFile, mkdir, readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import { fileURLToPath } from 'node:url';
import { Engine } from '../lib/engine.mjs';
import { ControlUnderTest } from './tun-control-adapter.mjs';
import { lineOutbound } from '../lib/apps.mjs';
import { launchSpec } from './server-under-test.mjs';
import { recordLaunch } from '../tests/windows/launch.mjs';
import { startHarness, run } from '../tests/windows/testisp/harness.mjs';
import { targets } from '../tests/windows/targets.mjs';
import { localHttps, startTrafficEngine } from './tun-test-https.mjs';
import { diagnoseControl } from './tun-test-diagnostics.mjs';

if (process.platform !== 'win32' || process.env.GITHUB_ACTIONS !== 'true' || process.env.RUNNER_ENVIRONMENT !== 'github-hosted') {
  throw new Error('TUN tests may run only on disposable GitHub-hosted Windows runners.');
}
const dir = path.resolve('dist/tun-test');
await mkdir(dir, { recursive: true });
const engineAdapter = process.argv.includes('--engine-adapter');
if (engineAdapter) {
  assert.equal(launchSpec.server.toLowerCase(), process.execPath.toLowerCase(),
    '--engine-adapter tests the Node Engine adapter; omit it to test another control executable');
  await recordLaunch({ ...launchSpec, entry: fileURLToPath(import.meta.url) }, path.join(dir, 'executables.json'));
  console.log('Launcher: direct Engine adapter with local TLS; no control server is launched.');
} else {
  await recordLaunch(launchSpec, path.join(dir, 'executables.json'));
  console.log(`Launcher: the selected control service (${launchSpec.server}) owns the routing lifecycle.`);
}
// A distinct executable path exercises process discovery and app pinning.
const clientExe = path.join(dir, 'test-app.exe');
await copyFile(process.execPath, clientExe);
const engine = engineAdapter
  ? new Engine({ singBoxPath: launchSpec.engine, dataDir: dir, mode: 'tun' })
  : new ControlUnderTest(dir);
const report = [];
function log(message) { console.log(message); report.push(message); }
async function network(action, adapter, timeoutMs = 45_000) {
  const started = Date.now();
  const child = spawn('powershell.exe', ['-NoProfile', '-ExecutionPolicy', 'Bypass', '-File',
    path.resolve('scripts/tun-test-network.ps1'), '-Action', action], {
    windowsHide: true, stdio: ['ignore', 'pipe', 'pipe'],
    env: { ...process.env, NETSWITCH_TEST_ADAPTER: String(adapter?.index ?? ''), NETSWITCH_TEST_STATIC_DNS: adapter?.staticDns ?? '' },
  });
  let output = '', errors = '';
  child.stdout.on('data', (chunk) => { output += chunk; });
  child.stderr.on('data', (chunk) => { errors += chunk; });
  let timedOut = false;
  const timer = setTimeout(() => { timedOut = true; child.kill(); }, timeoutMs);
  try {
    const [code, signal] = await once(child, 'exit');
    const result = timedOut ? `timed out after ${timeoutMs / 1000} seconds; PowerShell was killed` : `exited ${code}${signal ? ` (${signal})` : ''}`;
    assert.equal(code, 0, `Network ${action} ${result}: ${errors}\n${output}`);
    if (timeoutMs > 45_000) log(`ARM64 cold preflight network read completed in ${Date.now() - started} ms`);
    return JSON.parse(output.replace(/^\uFEFF/, '').trim());
  } finally { clearTimeout(timer); }
}
const worker = spawn(clientExe, [path.resolve('scripts/tun-test-client.mjs')], {
  windowsHide: true, stdio: ['ignore', 'inherit', 'inherit', 'ipc'],
});
let serial = 0;
const pending = new Map();
worker.on('message', ({ id, result, error }) => {
  const entry = pending.get(id);
  if (!entry) return;
  pending.delete(id); clearTimeout(entry.timer);
  if (error) entry.reject(new Error(error)); else entry.resolve(result);
});
worker.on('exit', (code) => {
  for (const entry of pending.values()) { clearTimeout(entry.timer); entry.reject(new Error(`Test app exited ${code}`)); }
  pending.clear();
});
function client(command, args = {}) {
  return new Promise((resolve, reject) => {
    const id = ++serial;
    const timer = setTimeout(() => { pending.delete(id); reject(new Error(`Test app ${command} timed out`)); }, 60_000);
    pending.set(id, { resolve, reject, timer });
    const target = httpsResponder?.target;
    worker.send({ id, command, ...(command === 'open' ? { target } : {}), ...args });
  });
}
function alive() { assert.equal(engine.status, 'on', engine.error ?? 'Engine crashed'); }
async function until(check, description, ms = 10_000) {
  const deadline = Date.now() + ms;
  let value;
  do {
    alive();
    value = await check();
    if (value) return value;
    await delay(200);
  } while (Date.now() < deadline);
  throw new Error(`Timed out: ${description}`);
}
async function routed(items, line) {
  let all;
  try { return await until(async () => {
    all = await engine.connections();
    return items.every(({ port }) => all.some((conn) =>
      Number(conn.metadata.sourcePort) === port &&
      conn.metadata.processPath?.toLowerCase() === clientExe.toLowerCase() &&
      conn.metadata.type === 'tun/tun-in' &&
      conn.chains.includes(lineOutbound(line)))) && all;
  }, `test app's ${items.length} connections through TUN to ${line}`); }
  catch (error) {
    log(`Expected sockets: ${JSON.stringify(items)}; observed engine connections: ${JSON.stringify(all)}`);
    throw error;
  }
}
async function clean(label, firstReadTimeout = 45_000) {
  let state;
  for (let attempt = 0; attempt < 3; attempt += 1) {
    state = await network('state', undefined, attempt === 0 ? firstReadTimeout : 45_000);
    if (Object.values(state).every((items) => items.length === 0)) { log(`ok - ${label}: no TUN adapter, routes or sing-tun firewall rules`); return; }
    await delay(500);
  }
  assert.fail(`${label}: leftovers ${JSON.stringify(state)}`);
}
let adapter;
let harness, responder, httpsResponder;
let restoreDns = false;
let suspendedEnginePid;
async function injectSuspension(action) {
  const result = await run('powershell.exe', ['-NoProfile', '-ExecutionPolicy', 'Bypass', '-File',
    path.resolve('scripts/tun-test-inject.ps1'), '-EnginePid', String(suspendedEnginePid), '-Action', action],
  { env: { PSModulePath: undefined } });
  log(result.stdout);
}
try {
  const pins = JSON.parse(await readFile('packaging/versions.json', 'utf8'));
  log(`Engine ${pins.singBox.version}, Windows ${process.arch}, Node ${process.version}`);
  // The first ARM64 PowerShell/Windows-provider read can exceed 45 s before
  // Control or TUN exists. Only this cold baseline read gets extra time;
  // every subsequent read and every routing/cleanup assertion keeps its bound.
  await clean('before start', process.arch === 'arm64' ? 90_000 : 45_000);
  adapter = await network('inspect');
  harness = await startHarness(path.join(dir, 'testisp'));
  responder = await targets(harness.uplink.address);
  httpsResponder = await localHttps(harness.uplink.address);
  log(`Local HTTPS fixture: ${httpsResponder.target.host}:443 -> ${httpsResponder.address}:${httpsResponder.port}; certificate name netswitch.invalid`);
  await harness.control('targets', { ports: [responder.direct.http, ...responder.direct.udp] });
  const udpTarget = { host: responder.virtual.host, port: responder.virtual.udp[0] };
  log(`Physical adapter: ${JSON.stringify(adapter)}`);
  const reuseTarget = { host: responder.virtual.host, port: responder.virtual.http };
  log(`PORT-REUSE direct baseline: ${JSON.stringify(await client('reuse', { target: reuseTarget, localAddress: harness.testisp.address }))}`);
  const udpSizes = [64, 1800];
  for (const size of udpSizes) {
    log(`UDP direct baseline: ${JSON.stringify(await client('udp', { size, target: udpTarget, localAddress: harness.testisp.address }))}`);
  }
  const lines = [{ id: 'aa', alias: adapter.alias }, { id: 'bb', alias: 'TestISP' }];
  await engine.setAppLines({ [clientExe]: 'bb' });
  if (engineAdapter) await startTrafficEngine(engine, lines, httpsResponder);
  else await engine.start({ lines, httpsResponder });
  alive();
  await engine.log.append(`[test] Engine ${pins.singBox.version} started; traffic fixture uses info-level output.`);
  const state = await network('state');
  assert(state.adapters.some((item) => item.Name === 'NetSwitch' && item.Status === 'Up'), JSON.stringify(state));
  assert(state.routes.length > 0, 'No TUN routes installed');
  assert.equal(state.firewall.length, 0, 'gVisor must not add a firewall rule');
  const tlsCount = async () => httpsResponder
    ? ((await harness.control('stats')).destinations[`${httpsResponder.address}:${httpsResponder.port}`] ?? 0) : 0;
  const beforeFirst = await tlsCount();
  const first = await client('open', { count: 3 });
  const connections = await routed(first, 'bb');
  assert.equal(await tlsCount() - beforeFirst, 3, 'The three bb TLS sockets must cross TestISP');
  log(`ok - pinned app received local HTTPS responses through TUN: ${JSON.stringify(connections.find((c) => Number(c.metadata.sourcePort) === first[0].port))}`);
  if (process.env.CONTROL_DIAGNOSTIC_FAILURE === '1') {
    assert(!engineAdapter, 'The diagnostic proof requires Control');
    suspendedEnginePid = Number(await readFile(path.join(dir, 'engine.pid'), 'utf8'));
    await injectSuspension('suspend');
    await client('open', { count: 1 });
    assert.fail('Injected suspended engine unexpectedly served a new HTTPS request');
  }

  await engine.setAppLines({ [clientExe]: 'aa' });
  // Local rule sets are watched asynchronously; wait for the new mapping while
  // keeping the original connections alive throughout.
  let changed;
  await until(async () => {
    changed = await client('open', { count: 1 });
    const all = await engine.connections();
    return all.some((c) => Number(c.metadata.sourcePort) === changed[0].port && c.chains.includes(lineOutbound('aa')));
  }, 'rewritten app rule taking effect');
  await routed(changed, 'aa');
  if (!engineAdapter) {
    // Exactly one public request, with verified TLS and no retry. It uses the
    // copied app through the TUN, on aa before that lane is pointed at bb.
    const publicTrace = await client('public');
    const publicConnections = await routed([publicTrace], 'aa');
    const record = publicConnections.find((c) => Number(c.metadata.sourcePort) === publicTrace.port);
    log(`ok - one public HTTPS trace through TUN on physical line aa: ${JSON.stringify({ ...publicTrace, engine: record })}`);
  }
  await client('refresh', { ids: first.map(({ id }) => id) });
  await routed(first, 'bb');
  log('ok - rewritten rules route new connections to aa; old bb connections still carry traffic');
  await client('close');

  const beforeMany = await tlsCount();
  const many = await client('open', { count: 100 });
  const manyRouted = await routed(many, 'aa');
  assert.equal(await tlsCount(), beforeMany, 'The aa TLS sockets must use the physical line');
  const beforeSelector = await engine.connections();
  const oldIds = new Set(beforeSelector.filter((c) => many.some(({ port }) => port === Number(c.metadata.sourcePort))).map((c) => c.id));
  assert.equal(oldIds.size, 100, `Before selector PUT: missing sockets ${JSON.stringify(many.filter(({ port }) =>
    !beforeSelector.some((c) => Number(c.metadata.sourcePort) === port)).map((item) => ({ ...item,
      lastEngineRecord: manyRouted.find((c) => Number(c.metadata.sourcePort) === item.port) })))}`);
  const started = performance.now();
  await engine.pointLaneAt('aa', 'bb');
  const elapsed = performance.now() - started;
  assert(elapsed < 1000, `Selector PUT took ${elapsed.toFixed(1)} ms`);
  const after = await engine.connections();
  const missing = beforeSelector.filter((c) => oldIds.has(c.id) && !after.some((current) => current.id === c.id));
  assert.equal(missing.length, 0, `Selector closed existing connections: ${JSON.stringify(missing.map((c) =>
    ({ id: c.id, sourcePort: c.metadata.sourcePort, chains: c.chains, lastEngineRecord: c })))}`);
  await client('refresh', { ids: many.map(({ id }) => id) });
  await routed(many, 'aa');
  const beforeNew = await tlsCount();
  const newer = await client('open', { count: 3 });
  await routed(newer, 'bb');
  assert.equal(await tlsCount() - beforeNew, 3, 'New TLS sockets must physically cross bb after the selector change');
  log('ok - TLS path counters: initial bb +3, 100 aa sockets +0, new bb +3 through TestISP');
  log(`ok - selector PUT ${elapsed.toFixed(1)} ms with 100 open connections; all old sockets reused, new connections use bb`);
  await client('close');

  for (const size of udpSizes) {
    const result = await client('udp', { size, target: udpTarget });
    await routed([result], 'bb');
    log(`ok - UDP through TUN: ${JSON.stringify(result)}`);
  }
  const reuse = await client('reuse', { target: reuseTarget });
  log(`PORT-REUSE TUN: ${JSON.stringify(reuse)}`);
  alive();

  const held = await client('open', { count: 5 });
  await routed(held, 'bb');
  await client('refresh', { ids: held.map(({ id }) => id) });
  const beforeDns = (await engine.connections()).filter((c) => held.some(({ port }) => port === Number(c.metadata.sourcePort))).map((c) => c.id);
  restoreDns = true;
  const changedDns = await network('dns-change', adapter);
  assert.notDeepEqual(changedDns, adapter.dns, 'DNS probe did not change server addresses');
  await delay(3000);
  alive();
  const remaining = (await engine.connections()).filter((c) => beforeDns.includes(c.id)).length;
  let refresh;
  try { await client('refresh', { ids: held.map(({ id }) => id) }); refresh = 'all original sockets still carry traffic'; }
  catch (error) { refresh = error.message; }
  log(`DNS-CHANGE ${pins.singBox.version}: ${remaining}/${beforeDns.length} original connections remain; ${refresh}; DNS=${JSON.stringify(changedDns)}`);
  const restored = await network('dns-restore', adapter);
  restoreDns = false;
  assert.deepEqual([restored].flat(), adapter.dns, 'DNS servers were not restored');
  log(`DNS restored: ${JSON.stringify(restored)}`);
  await delay(1000);
  alive();
  await client('close');
  await routed(await client('open', { count: 1 }), 'bb');
  log('ok - new HTTPS connection after DNS restoration');
  await client('close');
  // Save the interesting first run before lifecycle rotations replace its log.
  await engine.log.append('[test] Traffic probes finished; engine still running.');
  await writeFile(path.join(dir, 'traffic-engine.log'), await readFile(engine.logPath));
  await engine.stop();
  await clean('traffic fixture');
  // All 20 lifecycle cycles still use the unmodified product configuration.
  for (let cycle = 1; cycle <= 20; cycle += 1) {
    await engine.start({ lines });
    alive();
    await engine.stop();
    await clean(`cycle ${cycle}/20`);
  }
  log('TUN end-to-end test passed');
} catch (error) {
  log(`FAIL: ${error.stack}`);
  // Start all live reads immediately, before waiting on the client or cleanup.
  const liveDiagnostics = engineAdapter ? Promise.resolve() : diagnoseControl(engine, worker.pid, httpsResponder, log)
    .catch((cause) => log(`Control diagnostics failed: ${cause.stack}`));
  const sockets = await client('diagnostics').catch((cause) => ({ error: cause.message }));
  log(`TLS sockets at failure: ${JSON.stringify(sockets)}`);
  await writeFile(path.join(dir, 'https-client-failure.json'), JSON.stringify(sockets, null, 2));
  if (engineAdapter) {
    log(`Engine adapter at failure: ${JSON.stringify({ status: engine.status, error: engine.error,
      childPid: engine.child?.pid ?? null, exitCode: engine.child?.exitCode ?? null })}`);
  }
  await liveDiagnostics;
  log(`TLS responder events at failure: ${JSON.stringify(httpsResponder?.events ?? [])}`);
  for (const file of ['server.log', 'engine.log', 'traffic-engine.log']) {
    const text = await readFile(path.join(dir, file), 'utf8').catch(() => 'unavailable');
    log(`${file}:\n${file === 'server.log' ? text.split('\n').slice(-50).join('\n') : text}`);
  }
  log(`Control output:\n${engine.output}`);
  process.exitCode = 1;
} finally {
  if (suspendedEnginePid) await injectSuspension('resume');
  if (restoreDns) {
    try { log(`DNS restored in cleanup: ${JSON.stringify(await network('dns-restore', adapter))}`); }
    catch (error) { log(`DNS RESTORE FAILED: ${error.stack}`); process.exitCode = 1; }
  }
  if (worker.exitCode === null) worker.disconnect();
  try { await engine.stop(); await clean('final cleanup'); }
  catch (error) { log(`CLEANUP FAILED: ${error.stack}`); process.exitCode = 1; }
  try { if (!engineAdapter) await engine.quit(); }
  catch (error) { log(`CONTROL QUIT FAILED: ${error.stack}`); process.exitCode = 1; }
  if (harness) {
    try { log(`TestISP counters: ${JSON.stringify(await harness.control('stats'))}`); await harness.close(); }
    catch (error) { log(`TESTISP CLEANUP FAILED: ${error.stack}`); process.exitCode = 1; }
  }
  if (responder) await responder.close();
  if (httpsResponder) {
    await writeFile(path.join(dir, 'https-observations.json'), JSON.stringify(httpsResponder.seen, null, 2));
    log(`Local HTTPS responder: ${httpsResponder.seen.length} requests, ${new Set(httpsResponder.seen.map((item) => item.connection)).size} TLS sockets`);
    await httpsResponder.close();
    await writeFile(path.join(dir, 'https-events.json'), JSON.stringify(httpsResponder.events, null, 2));
  }
  await writeFile(path.join(dir, 'report.txt'), `${report.join('\n')}\n`);
}
