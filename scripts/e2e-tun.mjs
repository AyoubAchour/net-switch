// NEVER run this on a developer's PC. It changes routes and briefly changes DNS.
// The guard also excludes self-hosted runners. Engine uses the app's unchanged
// config, auto_route, checksum verification, rule writes and start/stop lifecycle.
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { copyFile, mkdir, readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import { Engine } from '../lib/engine.mjs';
import { lineOutbound } from '../lib/apps.mjs';

if (process.platform !== 'win32' || process.env.GITHUB_ACTIONS !== 'true' || process.env.RUNNER_ENVIRONMENT !== 'github-hosted') {
  throw new Error('TUN tests may run only on disposable GitHub-hosted Windows runners.');
}
const dir = path.resolve('dist/tun-test');
await mkdir(dir, { recursive: true });
// A distinct executable path exercises process discovery and app pinning.
const clientExe = path.join(dir, 'test-app.exe');
await copyFile(process.execPath, clientExe);
const engine = new Engine({ singBoxPath: path.resolve('engine/sing-box.exe'), dataDir: dir, mode: 'tun' });
const report = [];
function log(message) { console.log(message); report.push(message); }
async function network(action, adapter) {
  const child = spawn('powershell.exe', ['-NoProfile', '-ExecutionPolicy', 'Bypass', '-File',
    path.resolve('scripts/tun-test-network.ps1'), '-Action', action], {
    windowsHide: true, stdio: ['ignore', 'pipe', 'pipe'],
    env: { ...process.env, NETSWITCH_TEST_ADAPTER: String(adapter?.index ?? ''), NETSWITCH_TEST_STATIC_DNS: adapter?.staticDns ?? '' },
  });
  let output = '', errors = '';
  child.stdout.on('data', (chunk) => { output += chunk; });
  child.stderr.on('data', (chunk) => { errors += chunk; });
  const timer = setTimeout(() => child.kill(), 45_000);
  try {
    const [code] = await once(child, 'exit');
    assert.equal(code, 0, `Network ${action}: ${errors}\n${output}`);
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
    worker.send({ id, command, ...args });
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
async function clean(label) {
  let state;
  for (let attempt = 0; attempt < 3; attempt += 1) {
    state = await network('state');
    if (Object.values(state).every((items) => items.length === 0)) { log(`ok - ${label}: no TUN adapter, routes or sing-tun firewall rules`); return; }
    await delay(500);
  }
  assert.fail(`${label}: leftovers ${JSON.stringify(state)}`);
}
let adapter;
let restoreDns = false;
try {
  const pins = JSON.parse(await readFile('packaging/versions.json', 'utf8'));
  log(`Engine ${pins.singBox.version}, Windows ${process.arch}, Node ${process.version}`);
  await clean('before start');
  adapter = await network('inspect');
  log(`Physical adapter: ${JSON.stringify(adapter)}`);
  log(`PORT-REUSE direct baseline: ${JSON.stringify(await client('reuse'))}`);
  // Capture the runner's resolver before the later DNS-change experiment.
  // Both sizes are mandatory: an unavailable baseline fails instead of
  // silently removing UDP coverage from this run.
  const dnsServer = adapter.dns.find((address) => /^\d+\.\d+\.\d+\.\d+$/.test(address));
  assert(dnsServer, `No IPv4 runner DNS resolver: ${JSON.stringify(adapter.dns)}`);
  for (const size of [64, 1800]) {
    log(`UDP direct baseline: ${JSON.stringify(await client('udp', { size, server: dnsServer }))}`);
  }
  // Hosted runners have one physical internet adapter. Two independently tagged
  // outbounds on that adapter let the Clash API prove which line was selected.
  const lines = ['aa', 'bb'].map((id) => ({ id, alias: adapter.alias }));
  await engine.setAppLines({ [clientExe]: 'bb' });
  await engine.start({ lines });
  alive();
  // The app's warn-level log can legitimately be empty. Keep a marked test
  // header so the artifact exists even when the engine emitted no warnings.
  await engine.log.append(`[test] Engine ${pins.singBox.version} started; subsequent engine output uses the app's warn level.`);
  const state = await network('state');
  assert(state.adapters.some((item) => item.Name === 'NetSwitch' && item.Status === 'Up'), JSON.stringify(state));
  assert(state.routes.length > 0, 'No TUN routes installed');
  assert.equal(state.firewall.length, 0, 'gVisor must not add a firewall rule');
  const first = await client('open', { count: 3 });
  const connections = await routed(first, 'bb');
  log(`ok - pinned app received public HTTPS responses through TUN: ${JSON.stringify(connections.find((c) => Number(c.metadata.sourcePort) === first[0].port))}`);

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
  await client('refresh', { ids: first.map(({ id }) => id) });
  await routed(first, 'bb');
  log('ok - rewritten rules route new connections to aa; old bb connections still carry traffic');
  await client('close');

  const many = await client('open', { count: 100 });
  await routed(many, 'aa');
  const oldIds = new Set((await engine.connections()).filter((c) => many.some(({ port }) => port === Number(c.metadata.sourcePort))).map((c) => c.id));
  assert.equal(oldIds.size, 100);
  const started = performance.now();
  await engine.pointLaneAt('aa', 'bb');
  const elapsed = performance.now() - started;
  assert(elapsed < 1000, `Selector PUT took ${elapsed.toFixed(1)} ms`);
  const after = await engine.connections();
  assert([...oldIds].every((id) => after.some((c) => c.id === id)), 'Selector closed existing connections');
  await client('refresh', { ids: many.map(({ id }) => id) });
  await routed(many, 'aa');
  const newer = await client('open', { count: 3 });
  await routed(newer, 'bb');
  log(`ok - selector PUT ${elapsed.toFixed(1)} ms with 100 open connections; all old sockets reused, new connections use bb`);
  await client('close');

  for (const size of [64, 1800]) {
    const result = await client('udp', { size, server: dnsServer });
    await routed([result], 'bb');
    log(`ok - UDP through TUN: ${JSON.stringify(result)}`);
  }
  const reuse = await client('reuse');
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
  await clean('cycle 1/20');
  for (let cycle = 2; cycle <= 20; cycle += 1) {
    await engine.start({ lines });
    alive();
    await engine.stop();
    await clean(`cycle ${cycle}/20`);
  }
  log('TUN end-to-end test passed');
} catch (error) {
  log(`FAIL: ${error.stack}`);
  process.exitCode = 1;
} finally {
  if (restoreDns) {
    try { log(`DNS restored in cleanup: ${JSON.stringify(await network('dns-restore', adapter))}`); }
    catch (error) { log(`DNS RESTORE FAILED: ${error.stack}`); process.exitCode = 1; }
  }
  if (worker.exitCode === null) worker.disconnect();
  try { await engine.stop(); await clean('final cleanup'); }
  catch (error) { log(`CLEANUP FAILED: ${error.stack}`); process.exitCode = 1; }
  await writeFile(path.join(dir, 'report.txt'), `${report.join('\n')}\n`);
}
