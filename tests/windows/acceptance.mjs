import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { createWriteStream } from 'node:fs';
import { copyFile, mkdir, readFile, writeFile, unlink } from 'node:fs/promises';
import path from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import { recordLaunch, startServer, verifyEngineProcess } from './launch.mjs';
import { launchSpec } from '../../scripts/server-under-test.mjs';
import { BaselineDefect, Report } from './report.mjs';
import { targets } from './targets.mjs';
import { lifecycleOutput, timedPhase } from './lifecycle.mjs';
import { startInspection } from './inspection.mjs';
import { engineFirewall, plantUnrelatedFirewallRule } from './firewall.mjs';
import { hostedOnly, identity, run, startHarness, until } from './testisp/harness.mjs';
import { localTraffic, proveDefaultRoute } from './local-traffic.mjs';
import { httpsRoute } from '../../scripts/tun-test-https.mjs';
import { httpsMarker } from '../../scripts/control-test-https.mjs';

hostedOnly();
const options = launchSpec;
assert(['baseline', 'v1'].includes(options.profile), 'Use --profile baseline or v1');
const dir = path.resolve('dist/windows-acceptance');
const dataDir = path.join(dir, 'app');
await mkdir(dataDir, { recursive: true });
const report = new Report(options.profile, path.join(dir, 'report.json'));
const output = createWriteStream(path.join(dir, 'server-output.log'));
const serverOutput = lifecycleOutput((chunk) => output.write(chunk));
const clientExe = path.join(dir, 'acceptance-app.exe');
await copyFile(process.execPath, clientExe);
let harness, responder, tlsResponder, server, worker, dnsAdapter, quicServer, quic, inspection, unrelatedFirewall, restoreDNS = false;
const quicExe = path.resolve('dist/windows-test/quicprobe.exe');
const mtuExe = path.resolve('dist/windows-test/mtuprobe.exe');
const udpRejectExe = path.resolve('dist/windows-test/udpreject.exe');
const rejections = new Set(['ECONNRESET', 'ECONNREFUSED', 'EHOSTUNREACH', 'ENETUNREACH', 'EACCES']);
const publicDestination = '1.0.0.1:443';
const publicTarget = { host: '1.0.0.1', port: 443, path: '/cdn-cgi/trace', tls: true, publicTrace: true, servername: 'one.one.one.one' };
// The local TLS responder is reached through a test-only destination rewrite
// in today's sing-box config. The 1.0 engine (v1) has no such rewrite and no
// sing-box config, so v1 keeps its earlier public selection target for these
// checks; the baseline profile uses the local responder.
const localSelection = options.profile !== 'v1';
const selectionTarget = () => localSelection ? tlsResponder.target : publicTarget;
const selectionDestination = () => localSelection ? tlsResponder.destination : publicDestination;
const appDeviceIDs = new Set();
const destinationCount = (stats, destination) => stats.destinations?.[destination] ?? 0;
const udpSizes = [64, 1200, 1800, 8192, 12000, ...(options.profile === 'v1' ? [65000] : [])];

async function applied(route, body, matches) {
  await server.api(route, body);
  return until(async () => {
    const state = await server.api('state');
    return state.routing.status === 'on' && matches(state) && state;
  }, `${route} applied state`, 30_000);
}

async function pinApp(program, line) {
  return applied('app-line', { path: program, line }, (state) => {
    const app = state.apps.find((item) => item.path.toLowerCase() === program.toLowerCase());
    return (app?.line ?? null) === line;
  });
}

async function combine(on) {
  const state = await applied('combine', { on, mode: 'manual', weights: { [main.id]: 1, [second.id]: 1 } },
    (state) => state.combine.on === on && (!on || state.combine.active));
  await verifyTrafficConfig(`combining ${on ? 'on' : 'off'}`);
  return state;
}

function exactTraffic(before, after, expected, destination = publicDestination) {
  assert.equal(destinationCount(after, destination) - destinationCount(before, destination), expected,
    `Unexpected TestISP traffic to ${destination}: ${JSON.stringify({ before: before.destinations, after: after.destinations, expected })}`);
}
let main, second;
const pending = new Map();
let serial = 0;

// Independent probes keep reporting after a failure. The job still fails, and
// tests needing that baseline are explicitly blocked instead of counted as passes.
async function observe(name, label, fn) {
  try { return await report.test(name, label, fn); }
  catch { process.exitCode = 1; return undefined; }
}

function client(command, args = {}, timeout = 120_000) {
  return new Promise((resolve, reject) => {
    const id = ++serial;
    const timer = setTimeout(() => { pending.delete(id); reject(new Error(`${command}: client deadline`)); }, timeout);
    pending.set(id, { resolve, reject, timer }); worker.send({ id, command, ...args });
  });
}

// The engine's owner lookup is the only pre-handshake step with a documented
// allowance above the 100 ms freeze-gate bound (the 250 ms overload hold), so a
// slow sample needs its counters and the TCP table rows behind them.
const lookupCounters = ['count', 'misses', 'ambiguous', 'tcpHolds', 'tcpHeldFound', 'tcpHoldReads',
  'tcpLateIdentities', 'tcpRefreshes', 'cacheMissRefreshes', 'tcpRetries', 'tcpReadNanos', 'tcpIndexNanos'];
const lookupHistograms = ['buckets', 'snapshotBuckets', 'processBuckets', 'refreshBuckets', 'tcpReadBuckets'];

async function engineOwnerLookup() {
  try {
    const reply = await server.api('engine-command', { method: 'stats' });
    return (reply.engine ?? reply).ownerLookup ?? {};
  } catch (error) { return { error: String(error) }; }
}

function lookupSnapshot(lookup) {
  return { error: lookup.error, maxUS: lookup.maxUS, tcpReadMaxUS: lookup.tcpReadMaxUS, tcpHolds: lookup.tcpHolds,
    tcpHeldFound: lookup.tcpHeldFound, tcpHoldReads: lookup.tcpHoldReads,
    tcpLateIdentities: lookup.tcpLateIdentities, tcpRawRows: lookup.tcpRawRows,
    tcpPeakRows: lookup.tcpPeakRows, tcpRowsByFamily: lookup.tcpRowsByFamily, upperUS: lookup.upperUS };
}

function lookupDelta(before, after) {
  const delta = Object.fromEntries(lookupCounters.map((key) => [key, (after[key] ?? 0) - (before[key] ?? 0)]));
  for (const key of lookupHistograms) {
    const from = before[key] ?? [], to = after[key] ?? [], changed = {};
    for (let i = 0; i < to.length; i++) {
      const change = (to[i] ?? 0) - (from[i] ?? 0);
      if (change) changed[i] = change;
    }
    delta[key] = changed;
  }
  return delta;
}

// Evidence for a flow that got no reply: engine stats (lookups, dialer, Wintun
// counters, both ring headers and the registrar), the flow table and Control's
// state, twice 2 s apart to show what still moves, then one more attempt.
async function cycleFailureCapture() {
  const take = async () => {
    const [stats, state] = await Promise.all([
      server.api('engine-command', { method: 'stats' }).then((reply) => reply.engine ?? reply).catch(String),
      server.api('state').catch(String),
    ]);
    const flows = [];
    try {
      for (let cursor = '', pages = 0; pages < 20; pages++) {
        const page = await server.api('engine-command', { method: 'flows', fields: { cursor } });
        flows.push(...(page.flows ?? []));
        if (!page.cursor) break;
        cursor = page.cursor;
      }
    } catch (error) { flows.push({ error: String(error) }); }
    return { at: new Date().toISOString(), stats, flows, state };
  };
  const first = await take();
  await delay(2000);
  const second = await take();
  const retry = await client('open', { target: responder.virtual }).then((result) => ({ ok: true, result }), (error) => ({ ok: false, error: String(error) }));
  await client('close').catch(() => {});
  console.log(`WINDOWS CYCLE FAILURE CAPTURE ${JSON.stringify({ first: first.stats?.wintun, second: second.stats?.wintun, retry })}`);
  return { capture: [first, second], retry };
}

async function network(action, adapter) {
  if (action === 'state' && inspection) return inspection.query('network');
  const result = await run('powershell.exe', ['-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', path.resolve('scripts/tun-test-network.ps1'), '-Action', action], {
    env: { NETSWITCH_TEST_ADAPTER: String(adapter?.index ?? ''), NETSWITCH_TEST_STATIC_DNS: adapter?.staticDns ?? '' },
  });
  return JSON.parse(result.stdout.replace(/^\uFEFF/, ''));
}

async function clean() {
  return until(async () => {
    const state = await network('state');
    const pnp = await pnpDevices();
    assert(Object.values(state).every((list) => list.length === 0) && pnp.length === 0, JSON.stringify({ ...state, pnp }));
    if (options.profile === 'v1') await engineFirewall(options.engine, false);
    if (unrelatedFirewall) await unrelatedFirewall.check();
    return { ...state, pnp };
  }, 'no NetSwitch adapter (including non-present PnP), route or firewall leftovers', 20_000);
}

async function pnpDevices() {
  const value = inspection ? await inspection.query('pnp') :
    await run('powershell.exe', ['-NoProfile', '-File', path.resolve('tests/windows/pnp.ps1')])
      .then((result) => result.stdout ? JSON.parse(result.stdout) : []);
  return Array.isArray(value) ? value : [value];
}

function rememberAppDevices(devices) {
  for (const device of devices.filter((device) => device.present)) appDeviceIDs.add(device.instanceId);
}

async function stoppedSnapshot({ crashed = false } = {}) {
  const phases = {};
  const state = await timedPhase(phases, 'networkCheckMs', () => until(async () => {
    const value = await network('state');
    assert(Object.values(value).every((list) => list.length === 0), JSON.stringify(value));
    return value;
  }, 'stopped app routes and present adapters disappear', 20000));
  const pnp = await timedPhase(phases, 'pnpCheckMs', pnpDevices);
  assert(!pnp.some((device) => device.present), `Present device survived stop: ${JSON.stringify(pnp)}`);
  const firewall = options.profile === 'v1' ? await timedPhase(phases, 'firewallCheckMs',
    () => engineFirewall(options.engine, crashed, { live: !crashed })) : undefined;
  if (unrelatedFirewall) await unrelatedFirewall.check();
  return { state, pnp, phases, firewall };
}

async function recordOrphanPnP(name, label, state, pnp) {
  await observe(name, label, async () => {
    assert(pnp.every((device) => !device.present && appDeviceIDs.has(device.instanceId)), `Unrecognized PnP leftover: ${JSON.stringify(pnp)}`);
    if (pnp.length) throw new BaselineDefect('Engine exit left an owned, non-present Wintun device; Get-NetAdapter could not see it', { state, pnp });
    return { state, pnp };
  });
}

async function pin(line) {
  await client('close');
  await until(async () => {
    const state = await server.api('state');
    const app = state.apps.find((item) => item.path.toLowerCase() === clientExe.toLowerCase());
    return !app || Object.values(app.connections).every((count) => count === 0);
  }, 'previous test-app connections closed', 25_000);
  await pinApp(clientExe, line);
}

async function counts(total) {
  return until(async () => {
    const state = await server.api('state');
    const app = state.apps.find((item) => item.path.toLowerCase() === clientExe.toLowerCase());
    if (!app || Object.values(app.connections).reduce((sum, n) => sum + n, 0) < total) return null;
    return app.connections;
  }, `${total} real test-app flows in app state`, 25_000);
}

async function engineConnections() {
  const config = JSON.parse(await readFile(path.join(dataDir, 'engine-config.json'), 'utf8'));
  const { external_controller: controller, secret } = config.experimental.clash_api;
  assert(/^127\.0\.0\.1:\d+$/.test(controller), 'Expected the owned engine loopback API');
  const response = await fetch(`http://${controller}/connections`, {
    headers: { Authorization: `Bearer ${secret}` }, signal: AbortSignal.timeout(5000),
  });
  assert(response.ok, `Engine connections: HTTP ${response.status}`);
  return { pid: (await readFile(path.join(dataDir, 'engine.pid'), 'utf8')).trim(),
    connections: (await response.json()).connections };
}

async function newTrafficOn(line, target = selectionTarget(), count = 3) {
  await pin(line.id);
  const before = await harness.control('stats');
  const opened = await client('open', { count, target });
  const byLine = await counts(count);
  assert.equal(byLine[line.id], count, JSON.stringify(byLine));
  assert.equal(Object.values(byLine).reduce((sum, n) => sum+n, 0), count, 'Old sockets still counted');
  const after = await harness.control('stats');
  exactTraffic(before, after, line.id === second.id ? count : 0, target.publicTrace ? publicDestination : selectionDestination());
  const engine = target.publicTrace ? undefined : await selectedSockets(opened, line.id);
  return { opened, byLine, before, after, engine };
}

async function selectedSockets(opened, line) {
  const snapshot = await engineConnections();
  for (const item of opened) assert(snapshot.connections.some((c) =>
    Number(c.metadata.sourcePort) === item.port && c.metadata.processPath?.toLowerCase() === clientExe.toLowerCase()
    && c.metadata.type === 'tun/tun-in' && c.chains.includes(`line-${line}`)), `Missing engine socket on ${line}: ${JSON.stringify({ item, snapshot })}`);
  return snapshot;
}

// fault names the TestISP fault injected while waiting, or null once it is
// cleared, so a TestISP baseline failure during the fault isn't read as an
// outage of 1.1.1.1.
async function healthUntil(check, label, timeout, fault) {
  try { return await until(check, label, timeout); }
  catch (cause) {
    // These are independent diagnostics, never a retry of a failed health vote.
    const baselines = await Promise.all([harness.uplink, harness.testisp].map(async (line) => ({
      line: line.alias, endpoint: 'https://1.1.1.1/cdn-cgi/trace', at: new Date().toISOString(),
      activeFault: line === harness.testisp ? fault : null,
      result: await harness.probe(line).catch((error) => ({ error: error.message })),
    })));
    const injected = fault ? `Injected fault still active on TestISP: ${fault}; its TestISP baseline is expected to fail and is not a 1.1.1.1 outage.` : 'No injected fault was active.';
    throw new Error(`${cause.message}; health-vote origin unproven. ${injected} Independent public baseline evidence: ${JSON.stringify(baselines)}. Other product endpoints were not independently measured.`, { cause });
  }
}

async function publicBaseline() { return { direct: await harness.probe(harness.uplink), virtual: await harness.probe(harness.testisp) }; }

async function targetFirewall(action) {
  return run('powershell.exe', ['-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', path.resolve('tests/windows/target-network.ps1'), '-Action', action], {
    env: { ACCEPTANCE_CLIENT: clientExe, ACCEPTANCE_GATEWAY: path.resolve('dist/windows-test/testisp.exe'), ACCEPTANCE_ENGINE: options.engine, ACCEPTANCE_TARGET: harness?.uplink.address ?? '',
      ACCEPTANCE_UPLINK: String(harness?.uplink.index ?? ''), ACCEPTANCE_TESTISP: String(harness?.testisp.index ?? ''), ACCEPTANCE_UDP_PROBE: udpRejectExe,
      ACCEPTANCE_MTU: mtuExe, ACCEPTANCE_QUIC: quicExe },
  });
}

async function ping(host, source, size = 32, df = false) {
  const args = [host.includes(':') ? '-6' : '-4', '-n', '1', '-w', '3000', '-l', String(size)];
  if (host.includes(':') && !source) {
    // Windows' ICMP API can bypass program-scoped firewall rules. Require the
    // selected source to belong to the app TUN and bind ping to that source.
    const selected = JSON.parse((await run('powershell.exe', ['-NoProfile', '-Command',
      'Find-NetRoute -RemoteIPAddress $env:ACCEPTANCE_PING_TARGET | Where-Object { $_.PSObject.Properties.Name -contains "IPAddress" } | Select-Object IPAddress,InterfaceAlias | ConvertTo-Json -Compress'],
    { env: { ACCEPTANCE_PING_TARGET: host } })).stdout);
    assert.equal(selected.InterfaceAlias, 'NetSwitch', `IPv6 echo would bypass the engine: ${JSON.stringify(selected)}`);
    assert.notEqual(selected.IPAddress, '2001:db8:19::1', 'IPv6 echo selected TestISP directly');
    source = selected.IPAddress;
  }
  if (source && host.includes(':')) args.push('-S', source);
  if (df) args.push('-f');
  args.push(host);
  const result = await run('ping.exe', args, { timeout: 10_000 });
  assert.match(result.stdout, /(?:time[=<]|TTL=)/i, 'Ping had no actual echo reply');
  return { output: result.stdout, source };
}

async function quicProbe(host, source, index) {
  const port = quic.address.split(':').at(-1);
  const args = ['--address', `${host}:${port}`, '--certificate', quic.certificate];
  if (source) args.push('--source', source);
  if (index) args.push('--interface', String(index));
  const result = await run(quicExe, args, { timeout: 20_000 });
  return JSON.parse(result.stdout);
}

async function verifyTrafficConfig(phase, marker) {
  if (!localSelection) return; // v1 writes no sing-box config to compare
  const rule = JSON.parse(marker ?? await readFile(path.join(dataDir, httpsMarker), 'utf8'));
  const product = JSON.parse(await readFile(path.join(dataDir, 'traffic-product-config.json'), 'utf8'));
  const actual = JSON.parse(await readFile(path.join(dataDir, 'engine-config.json'), 'utf8'));
  assert.deepEqual(rule, httpsRoute(tlsResponder), 'The marker must name this TLS responder');
  assert.deepEqual(actual.route.rules.shift(), rule);
  assert.equal(actual.log.level, 'info'); actual.log.level = product.log.level;
  assert.deepEqual(actual, product, 'Only the local TLS rewrite and diagnostic log level may change');
  console.log(`Traffic config verified: ${phase}; only TLS destination rewrite and diagnostic log level differ`);
}

async function start() {
  server = await startServer(options, dataDir, serverOutput);
  const state = await server.on();
  const marker = await readFile(path.join(dataDir, httpsMarker), 'utf8').catch((error) => { if (error.code === 'ENOENT') return null; throw error; });
  if (marker) await verifyTrafficConfig('startup', marker);
  await verifyEngineProcess(options, dataDir);
  rememberAppDevices(await pnpDevices());
  if (options.profile === 'v1') await engineFirewall(options.engine, true);
  return state;
}

async function mtuProbe(host, size, source, index) {
  const args = ['--address', `${host.includes(':') ? `[${host}]` : host}:${responder.virtual.udp[0]}`, '--size', String(size)];
  if (source) args.push('--source', source);
  if (index) args.push('--interface', String(index));
  return JSON.parse((await run(mtuExe, args, { timeout: 10_000 })).stdout);
}

async function udpReject(target, count = 100, timeout = 5000) {
  return JSON.parse((await run(udpRejectExe, ['--address', `${target.host}:${target.udp[0]}`, '--count', String(count), '--timeout', `${Math.ceil(timeout)}ms`], { timeout: 10_000 })).stdout);
}

try {
  inspection = await startInspection();
  await recordLaunch(options, path.join(dir, 'executables.json'));
  await report.test('clean before start', 'harness-baseline', clean);
  if (options.profile === 'v1') unrelatedFirewall = await plantUnrelatedFirewallRule();
  dnsAdapter = await network('inspect');
  harness = await startHarness(path.join(dir, 'testisp'));
  tlsResponder = await localTraffic(harness, dir);
  responder = await targets(harness.uplink.address);
  await targetFirewall('allow');
  await targetFirewall('ipv6');
  await writeFile(path.join(dir, 'quic-executable.json'), JSON.stringify(await identity(quicExe), null, 2));
  await writeFile(path.join(dir, 'mtu-executable.json'), JSON.stringify(await identity(mtuExe), null, 2));
  await writeFile(path.join(dir, 'udp-reject-executable.json'), JSON.stringify(await identity(udpRejectExe), null, 2));
  const quicState = path.join(dir, `quic-ready-${Date.now()}.json`);
  quicServer = spawn(quicExe, ['--serve', '--address', `${harness.uplink.address}:0`, '--interface', String(harness.uplink.index), '--state', quicState], {
    windowsHide: true, stdio: ['ignore', 'pipe', 'pipe'],
  });
  quicServer.stdout.on('data', (chunk) => output.write(chunk)); quicServer.stderr.on('data', (chunk) => output.write(chunk));
  quic = await until(async () => JSON.parse(await readFile(quicState, 'utf8')), 'controlled QUIC target ready');
  await harness.control('targets', { ports: [responder.direct.http, ...responder.direct.udp, Number(quic.address.split(':').at(-1))] });
  worker = spawn(clientExe, [path.resolve('tests/windows/client.mjs')], { windowsHide: true, stdio: ['ignore', 'inherit', 'inherit', 'ipc'] });
  worker.on('message', ({ id, result, error }) => {
    const entry = pending.get(id); if (!entry) return;
    pending.delete(id); clearTimeout(entry.timer);
    if (error) entry.reject(new Error(error)); else entry.resolve(result);
  });
  worker.on('exit', (code) => { for (const entry of pending.values()) { clearTimeout(entry.timer); entry.reject(new Error(`Client exited ${code}`)); } pending.clear(); });
  await report.test('both public egress baselines', 'harness-baseline', publicBaseline);
  await report.test('local TLS requires the TestISP default route', 'harness-baseline', () => proveDefaultRoute(harness, tlsResponder));
  await report.test('real QUIC v1 baseline on both line addresses', 'harness-baseline', async () => ({
    direct: await quicProbe(harness.uplink.address, harness.uplink.address, harness.uplink.index),
    virtual: await quicProbe(responder.virtual.host, harness.testisp.address, harness.testisp.index),
  }));
  await report.test('controlled HTTP reachable through both line addresses', 'harness-baseline', async () => {
    const direct = await client('open', { target: responder.direct }); await client('close');
    const before = await harness.control('stats');
    const virtual = await client('open', { target: { ...responder.virtual, source: harness.testisp.address } }); await client('close');
    const after = await harness.control('stats');
    assert(after.testisp.connections > before.testisp.connections);
    return { direct, virtual, before, after };
  });
  for (const size of udpSizes) {
    await report.test(`controlled UDP baseline ${size} bytes on both lines`, 'harness-baseline', async () => ({
      direct: await client('udp', { target: responder.direct, size }),
      virtual: await client('udp', { target: responder.virtual, size, localAddress: harness.testisp.address }),
    }));
  }
  const rejectBaseline = await observe('Windows reports controlled closed TCP and UDP ports', 'harness-baseline', async () => {
    const tcp = await client('reject', { target: responder.rejected, count: 3 });
    const udp = await udpReject(responder.rejected, 3);
    assert([...tcp, ...udp].every((sample) => rejections.has(sample.outcome)), `Closed ports did not report rejection: ${JSON.stringify({ tcp, udp })}`);
    return { tcp, udp };
  });
  const resetBaseline = await observe('RST survives both native and TestISP relays', 'harness-baseline', async () => {
    const direct = await client('reset', { target: responder.direct });
    const virtual = await client('reset', { target: { ...responder.virtual, source: harness.testisp.address } });
    assert.equal(direct.outcome, 'ECONNRESET', JSON.stringify(direct));
    assert.equal(virtual.outcome, 'ECONNRESET', JSON.stringify(virtual));
    return { direct, virtual };
  });
  await report.test('gateway preserves STUN mapping before engine starts', 'harness-baseline', async () => {
    const result = await client('udp', { target: responder.virtual, stun: true, localAddress: harness.testisp.address });
    assert.equal(new Set(result.mappings.map((item) => item.port)).size, 1, JSON.stringify(result));
    assert(result.unsolicited, `The gateway lost the third, uncontacted STUN sender: ${JSON.stringify({ result, stats: await harness.control('stats'), target: responder.seen.slice(-5) })}`);
    return result;
  });
  const directReuse = await observe('physical controlled port reuse baseline', 'harness-baseline', async () => {
    const peers = await responder.reuseTargets(1000);
    try {
      const samples = await client('reuse', { target: { ...peers.target, source: harness.uplink.address }, count: 1000 });
      const failed = samples.find((sample) => sample.outcome !== 'closed');
      let sockets;
      if (failed) sockets = await run('powershell.exe', ['-NoProfile', '-Command', `@(Get-NetTCPConnection | Where-Object { $_.LocalPort -eq ${failed.port} -or $_.RemotePort -eq ${failed.port} } | Select-Object LocalAddress,LocalPort,RemoteAddress,RemotePort,State,OwningProcess,CreationTime) | ConvertTo-Json -Compress`]);
      assert(samples.length === 1000 && !failed, `Physical reuse failed: ${JSON.stringify({ samples, sockets, target: peers.target })}`);
      assert.equal(new Set(samples.map((sample) => sample.port)).size, 1, 'Native source port changed');
      assert.equal(new Set(samples.map((sample) => sample.peerPort)).size, 1000, 'Native responder port was reused');
      for (const sample of samples) {
        const seen = JSON.parse(sample.body);
        assert.equal(seen.source, harness.uplink.address);
        assert.equal(seen.port, samples[0].port, 'Responder saw a different native source port');
      }
      return samples;
    } finally { await peers.close(); }
  });
  const gatewayReuse = await observe('TestISP 1,000 rapid fixed-tuple reuses', 'harness-baseline', async () => {
    assert.equal(harness.testisp.tcpReuseHook, true, 'TestISP must install the shared TIME_WAIT hook');
    const rounds = [];
    let samples;
    // Consecutive rounds expose occasional relay delays. Every round must
    // pass; a failure stops immediately and is never retried into a pass.
    for (let round = 1; round <= 4; round++) {
      const before = await harness.control('diagnostics');
      samples = await client('reuse', { target: { ...responder.virtual, source: harness.testisp.address }, count: 1000, warmup: true, maxMs: 100, diagnostics: harness.diagnosticClient });
      const after = await harness.control('diagnostics');
      const failed = samples.find((sample) => sample.outcome !== 'closed' || sample.ms >= 100);
      const stats = failed && await harness.control('stats');
      let sockets;
      if (failed) sockets = await run('powershell.exe', ['-NoProfile', '-Command', `@(Get-NetTCPConnection -LocalPort ${failed.port} -ErrorAction SilentlyContinue | Select-Object LocalAddress,LocalPort,RemoteAddress,RemotePort,State,OwningProcess) | ConvertTo-Json -Compress`]);
      if (samples.length !== 1000 || failed) {
        const error = new Error(`Gateway reuse failed: ${JSON.stringify({ round, count: samples.length, failed, trace: stats.tcpTrace })}`);
        error.evidence = { rounds, samples, sockets, stats, before, after };
        throw error;
      }
      assert.equal(new Set(samples.map((sample) => `${sample.port}:${sample.peerPort}`)).size, 1, 'TestISP reuse changed the tuple');
      const result = { round, count: samples.length, maxMs: Math.max(...samples.map((sample) => sample.ms)), tuple: [samples[0].port, samples[0].peerPort], architecture: process.arch };
      rounds.push({ ...result, before, after, clientHeartbeat: await client('heartbeat') });
      console.log(`TESTISP REUSE ${JSON.stringify(result)}`);
    }
    return { rounds, samples };
  });
  const icmpBaseline = await observe('controlled ICMP v4/v6 baselines', 'harness-baseline', async () => ({
    v4: await ping(responder.virtual.host, harness.testisp.address),
    v6: await ping('2001:db8:198::2', '2001:db8:19::1'),
  }));
  const ipv6Target = { ...responder.virtual, host: '2001:db8:198::2' };
  const ipv6Baseline = await observe('controlled IPv6 TCP and UDP baselines', 'harness-baseline', async () => {
    const tcp = await client('open', { target: { ...ipv6Target, source: '2001:db8:19::1' } }); await client('close');
    const udp = await client('udp', { target: ipv6Target, localAddress: '2001:db8:19::1' });
    return { tcp, udp };
  });
  if (options.profile === 'v1') {
    for (const size of [12000, 65000]) {
      await report.test(`IPv6 fragmented UDP reply baseline ${size} bytes`, 'harness-baseline',
        () => client('udp', { target: ipv6Target, localAddress: '2001:db8:19::1', replySize: size }));
    }
  }
  const mtuBaselines = {};
  for (const [host, source] of [[responder.virtual.host, harness.testisp.address], [ipv6Target.host, '2001:db8:19::1']]) {
    mtuBaselines[host] = await observe(`DF and oversize UDP baseline ${host}`, 'harness-baseline', async () => {
      const small = await mtuProbe(host, 1200, source, harness.testisp.index);
      assert.equal(small.outcome, 'reply', JSON.stringify(small));
      const large = await mtuProbe(host, 2000, source, harness.testisp.index);
      assert.equal(large.outcome, 'message-too-large', JSON.stringify(large));
      return { small, large };
    });
  }
  await writeFile(path.join(dataDir, 'settings.json'), JSON.stringify({ checkForUpdates: false }));
  if (localSelection) await writeFile(path.join(dataDir, httpsMarker), JSON.stringify(httpsRoute(tlsResponder)));
  await targetFirewall('capture');
  await report.test('IPv6 probes cannot bypass the stopped engine', 'harness-baseline', async () => {
    await assert.rejects(client('udp', { target: ipv6Target }));
    await assert.rejects(ping(ipv6Target.host));
    const mtu = await mtuProbe(ipv6Target.host, 1200).catch((error) => ({ outcome: 'blocked', error: error.message }));
    assert.notEqual(mtu.outcome, 'reply', JSON.stringify(mtu));
    return { udp: 'blocked', ping: 'blocked', mtu };
  });
  const initial = await start();
  main = initial.lines[0];
  assert.equal(main.alias, harness.uplink.alias, 'Default line is not the real uplink');
  await server.api('lines/add', { alias: 'TestISP' });
  const state = await server.on();
  second = state.lines.find((line) => line.alias === 'TestISP');
  assert(second && state.lines.length === 2, JSON.stringify(state.lines));
  await verifyTrafficConfig('two lines');
  await report.test('pins select both interfaces; secondary traffic crosses TestISP', 'parity', async () => ({ direct: await newTrafficOn(main), virtual: await newTrafficOn(second) }));
  await report.test('new pin leaves old connections alive', 'parity', async () => {
    const original = await client('open', { count: 3, target: selectionTarget() });
    await pinApp(clientExe, main.id);
    const next = await client('open', { count: 3, target: selectionTarget() });
    await client('refresh', { ids: original.map((item) => item.id) });
    const byLine = await counts(9);
    assert(byLine[second.id] >= 6 && byLine[main.id] === 3, JSON.stringify(byLine));
    if (localSelection) { await selectedSockets(original, second.id); await selectedSockets(next, main.id); }
    return { original, next, byLine };
  });
  await pin(null);
  await report.test('combining selects both interfaces and forwards the secondary share through TestISP', 'parity', async () => {
    await pin(null);
    await combine(true);
    const before = await harness.control('stats');
    const opened = await client('open', { count: 40, target: selectionTarget() });
    const byLine = await counts(40);
    assert(byLine[main.id] >= 10 && byLine[second.id] >= 10, JSON.stringify(byLine));
    const after = await harness.control('stats');
    exactTraffic(before, after, byLine[second.id], selectionDestination());
    if (localSelection) {
      const snapshot = await engineConnections();
      for (const line of [main, second]) {
        const items = opened.filter(({ port }) => snapshot.connections.some((c) => Number(c.metadata.sourcePort) === port && c.chains.includes(`line-${line.id}`)));
        assert.equal(items.length, byLine[line.id]); await selectedSockets(items, line.id);
      }
    }
    await client('close');
    await combine(false);
    return { byLine, before, after };
  });
  for (const fault of ['withdraw', 'drop']) await report.test(`${fault === 'withdraw' ? 'default-route loss' : 'dead gateway with route present'} fails over and restoration fails back`, 'parity', async () => {
    const injected = fault === 'withdraw' ? 'default route withdrawn' : 'gateway drop mode';
    await pin(second.id);
    if (fault === 'withdraw') await harness.network('withdraw');
    else await harness.control('mode', { mode: 'drop' });
    try {
      const failedOver = await healthUntil(async () => {
        const state = await server.api('state');
        return state.lines.find((line) => line.id === second.id)?.target === main.id && state.lines;
      }, 'TestISP failover', 60_000, injected);
      const routes = await harness.network('state');
      assert.equal(routes.defaultRoute, fault === 'drop', 'Fault injection changed the wrong failure domain');
      const before = await harness.control('stats');
      await client('open', { count: 3, target: publicTarget });
      const byLine = await counts(3); assert.equal(byLine[main.id], 3);
      const after = await harness.control('stats');
      exactTraffic(before, after, 0);
      if (fault === 'withdraw') await harness.network('restore');
      else await harness.control('mode', { mode: 'running' });
      const failedBack = await healthUntil(async () => {
        const state = await server.api('state');
        return state.lines.find((line) => line.id === second.id)?.target === second.id && state.lines;
      }, 'TestISP failback', 90_000, null);
      return { fault, routes, failedOver, byLine, before, after, failedBack, traffic: await newTrafficOn(second) };
    } finally {
      if (fault === 'drop') await harness.control('mode', { mode: 'running' });
      // restore is idempotent when a route is already present.
      else await harness.network('restore');
    }
  });
  // Later restarts and all lifecycle cycles use the ordinary product config.
  // The running engine keeps the config it started with, so the rewrite rule
  // and info logging stay until the next engine start, when the ICMP case
  // reorders the lines. The controlled HTTP, reset, UDP, STUN, QUIC, IPv6 and
  // DF cases run on it before then. The rule is inert for them: it matches
  // only TCP to 203.0.113.44:443, and they address the controlled responder.
  if (localSelection) await unlink(path.join(dataDir, httpsMarker));
  await pin(second.id);
  await report.test('controlled HTTP crosses the app TUN and TestISP', 'parity', async () => {
    const before = await harness.control('stats');
    const response = await client('open', { target: responder.virtual });
    const byLine = await counts(1); assert.equal(byLine[second.id], 1);
    const after = await harness.control('stats'); assert(after.testisp.connections > before.testisp.connections);
    await client('close'); return { response, byLine, before, after };
  });
  await observe('TCP reset crosses the app TUN unchanged', 'baseline-defect', async () => {
    assert(resetBaseline, 'Blocked: the reset baseline failed');
    const result = await client('reset', { target: responder.virtual });
    if (result.outcome === 'fin') throw new BaselineDefect('The engine converts an upstream RST into FIN', { resetBaseline, result });
    assert.equal(result.outcome, 'ECONNRESET', JSON.stringify(result));
    return result;
  });
  for (const size of udpSizes) {
    await observe(`UDP payload and fragmentation through TUN: ${size} bytes`, 'parity', () => client('udp', { target: responder.virtual, size }));
  }
  await observe('STUN two-server mapping through TUN', 'parity', async () => {
    const result = await client('udp', { target: responder.virtual, stun: true });
    assert.equal(new Set(result.mappings.map((item) => item.port)).size, 1, JSON.stringify(result));
    assert(result.unsolicited, 'The app lost the third, uncontacted STUN sender');
    return result;
  });
  if (options.profile === 'v1') {
    await client('close');
    const { udpIdentity } = await import('./udp-identity.mjs');
    for (const blocked of [false, true]) {
      await observe(`UDP source-port reuse by an app with ${blocked ? 'a blocked pin' : 'the opposite pin'} changes policy within 1 second`, 'parity',
        () => udpIdentity({ server, responder, directory: dir, main, second, blocked }));
    }
  }
  await observe('real QUIC v1 through TUN has the right payload hash', 'parity', async () => {
    await pinApp(quicExe, second.id);
    const before = await harness.control('stats');
    const response = await quicProbe(responder.virtual.host);
    const after = await harness.control('stats');
    assert(after.testisp.bytesIn > before.testisp.bytesIn && after.testisp.bytesOut > before.testisp.bytesOut);
    return { response, before, after };
  });
  await observe('controlled IPv6 TCP and UDP through TUN', 'parity', async () => {
    assert(ipv6Baseline, 'Blocked: the controlled IPv6 baseline failed');
    assert.equal((await server.api('state')).routing.ipv6, true, 'IPv6 capture was not enabled');
    const tcp = await client('open', { target: ipv6Target });
    const byLine = await counts(1); assert(byLine[second.id] >= 1); await client('close');
    const udp = await client('udp', { target: ipv6Target }); return { tcp, udp, byLine };
  });
  if (options.profile === 'v1') {
    for (const size of [12000, 65000]) {
      await report.test(`IPv6 fragmented UDP reply through TUN ${size} bytes`, 'parity',
        () => client('udp', { target: ipv6Target, replySize: size }));
    }
  }
  await pinApp(mtuExe, second.id);
  for (const host of [responder.virtual.host, ipv6Target.host]) {
    await observe(`DF and oversize UDP through TUN ${host}`, 'baseline-defect', async () => {
      assert(mtuBaselines[host], 'Blocked: the controlled DF baseline failed');
      const small = await mtuProbe(host, 1200);
      assert.equal(small.outcome, 'reply', JSON.stringify(small));
      if (host.includes(':')) assert(!small.source.startsWith('[2001:db8:19::1]:'), `MTU probe bypassed the TUN: ${JSON.stringify(small)}`);
      const large = await mtuProbe(host, 2000);
      if (host.includes(':')) assert(!large.source.startsWith('[2001:db8:19::1]:'), `MTU probe bypassed the TUN: ${JSON.stringify(large)}`);
      if (large.outcome === 'reply') throw new BaselineDefect('Oversize UDP succeeds instead of reporting packet too large', { baseline: mtuBaselines[host], small, large });
      assert.equal(large.outcome, 'message-too-large', JSON.stringify(large));
      return { small, large };
    });
  }
  await observe('ICMP v4/v6 and 1400-byte MTU probes through TUN', 'parity', async () => {
    assert(icmpBaseline, 'Blocked: the controlled ICMP baseline failed');
    await server.api('lines/order', { ids: [second.id, main.id] }); await server.on();
    try {
      const before = await harness.control('stats');
      const result = { v4: await ping(responder.virtual.host), v6: await ping(ipv6Target.host),
        mtu4: await ping(responder.virtual.host, undefined, 1400, true), mtu6: await ping(ipv6Target.host, undefined, 1400) };
      const after = await harness.control('stats');
      for (const host of [responder.virtual.host, ipv6Target.host]) assert((after.echoRequests?.[host] ?? 0) >= (before.echoRequests?.[host] ?? 0) + 2, `Echo replies for ${host} did not reach the controlled path`);
      return { result, before, after };
    } finally { await server.api('lines/order', { ids: [main.id, second.id] }); await server.on(); }
  });
  const reuseReady = directReuse && gatewayReuse;
  if (!reuseReady) report.results.push({ name: 'freeze gate', label: 'baseline-defect', status: 'blocked', reason: 'Native or fixed-tuple TestISP reuse prerequisite failed; no engine conclusion is possible.' });
  for (const gap of reuseReady ? [0, 10, 100, 500] : []) {
    await observe(`freeze gate: ${gap} ms port reuse`, 'baseline-defect', async () => {
      const samples = await client('reuse', { target: responder.virtual, count: gap ? 10 : 1000, warmup: true, gap });
      const failure = samples.find((sample) => sample.outcome !== 'closed' || sample.ms >= 100);
      // The warm-up already proved a fresh connection on this tuple. Attempt
      // one is now a reuse too, so its stall is the same baseline defect.
      if (failure?.outcome === 'timeout') {
        let recovery;
        if (gap === 0) {
          const started = performance.now();
          await delay(62_000);
          recovery = await client('reuse', { target: responder.virtual, count: 1, reusePort: failure.port });
          assert.equal(recovery[0].outcome, 'closed', 'Port did not recover after the expected TIME_WAIT interval');
          recovery = { afterMs: performance.now() - started, samples: recovery };
        }
        throw new BaselineDefect('A reusable app port stalls behind the TUN after a successful passive close', { samples, directReuse, gatewayReuse, recovery });
      }
      assert(!failure, JSON.stringify(failure));
      return { count: samples.length, maxMs: Math.max(...samples.map((sample) => sample.ms)) };
    });
  }
  const large = await observe('100 MB TCP transfer with a payload hash', 'parity', async () => {
    const samples = await client('reuse', { target: responder.virtual, count: 1, length: 100_000_000 });
    assert.equal(samples[0]?.outcome, 'closed', JSON.stringify(samples)); return samples;
  });
  if (reuseReady && large) await observe('freeze gate: reuse after 100 MB transfer', 'baseline-defect', async () => {
    // The verified transfer is already the warm-up on this exact tuple. Keep
    // the first timed attempt immediately after it to test large-transfer reuse.
    console.log(`REUSE WARMUP (verified 100 MB transfer) ${JSON.stringify({ port: large[0].port, peerPort: large[0].peerPort, ms: large[0].ms })}`);
    const before = await engineOwnerLookup();
    // Same evidence options as the TestISP baseline: keep sampling past the
    // first slow attempt, and capture the client heartbeat and gateway trace
    // there. The engine counters are cumulative, so taking them after the loop
    // still shows whether the slow sample sat behind an owner-lookup hold.
    const samples = await client('reuse', { target: responder.virtual, count: 1000, reusePort: large[0].port,
      maxMs: 100, diagnostics: harness.diagnosticClient, continueAfterSlow: true });
    const after = await engineOwnerLookup();
    const heartbeat = await client('heartbeat').catch((error) => ({ error: String(error) }));
    const firstSlow = samples.find((sample) => sample.outcome !== 'closed' || sample.ms >= 100);
    const gateway = firstSlow?.diagnostics;
    for (const sample of samples) delete sample.diagnostics;
    if (firstSlow) {
      const gaps = gateway?.clientHeartbeat?.gaps ?? [];
      console.log(`FREEZE_GATE_SLOW_SAMPLE ${JSON.stringify({
        attempt: firstSlow.attempt, outcome: firstSlow.outcome, ms: firstSlow.ms,
        bindRetries: firstSlow.bindRetries, startedAt: firstSlow.startedAt, phases: firstSlow.phases,
        ownerLookup: { before: lookupSnapshot(before), after: lookupSnapshot(after), delta: lookupDelta(before, after) },
        clientHeartbeat: { periodMs: gateway?.clientHeartbeat?.periodMs, ticks: gateway?.clientHeartbeat?.ticks,
          maxGapMs: gateway?.clientHeartbeat?.maxGapMs, totalGaps: gaps.length,
          slowGaps: gaps.filter((gap) => gap.to >= (firstSlow.startedAt - 1000) * 1000
            && gap.from <= (firstSlow.startedAt + firstSlow.ms + 1000) * 1000) },
        gatewayTrace: gateway?.stats?.tcpTrace?.slice(-32),
      })}`);
    }
    console.log(`FREEZE_GATE_SUMMARY ${JSON.stringify({ count: samples.length,
      maxMs: samples.length ? Math.max(...samples.map((sample) => sample.ms)) : null,
      slowAttempt: firstSlow?.attempt ?? null,
      ownerLookup: { after: lookupSnapshot(after), delta: lookupDelta(before, after) },
      clientHeartbeat: { error: heartbeat.error, maxGapMs: heartbeat.maxGapMs, ticks: heartbeat.ticks,
        gaps: heartbeat.gaps?.length } })}`);
    if (samples.some((sample) => sample.outcome === 'timeout')) throw new BaselineDefect('Port stalls after a verified 100 MB transfer', samples);
    assert(samples.length === 1000 && samples.every((sample) => sample.outcome === 'closed' && sample.ms < 100), JSON.stringify(samples));
    return samples;
  });
  await report.test('DNS change leaves held sockets alive', 'parity', async () => {
    await client('close');
    const held = await client('open', { count: 5, target: responder.virtual });
    const beforePID = await readFile(path.join(dataDir, 'engine.pid'), 'utf8');
    restoreDNS = true;
    const changed = await network('dns-change', dnsAdapter);
    assert.notDeepEqual(changed, dnsAdapter.dns);
    await until(async () => {
      const actual = await network('dns-state', dnsAdapter);
      assert.deepEqual(actual, changed);
      return actual;
    }, 'Windows applied the requested DNS servers');
    // Keep exercising the original sockets across asynchronous network-change
    // notifications. This is an observation window, not a readiness sleep.
    const deadline = Date.now() + 10_000;
    let refreshes = 0;
    do {
      await client('refresh', { ids: held.map((item) => item.id) });
      assert.equal(await readFile(path.join(dataDir, 'engine.pid'), 'utf8'), beforePID, 'DNS change restarted the engine');
      refreshes++;
      await delay(200);
    } while (Date.now() < deadline);
    const after = await server.api('state'); assert.equal(after.routing.status, 'on');
    const afterPID = await readFile(path.join(dataDir, 'engine.pid'), 'utf8');
    assert.equal(afterPID, beforePID, 'DNS change restarted the engine');
    await network('dns-restore', dnsAdapter); restoreDNS = false;
    await client('close');
    await client('open', { target: responder.virtual }); await client('close');
    return { changed, held, beforePID, afterPID, refreshes };
  });
  await report.test('cap exhaustion closes old secondary flows and preserves main flows', 'parity', async () => {
    const prepare = async (stage, fn) => {
      const started = performance.now();
      try { return await fn(); }
      catch (cause) {
        const error = new Error(`${stage}: ${cause.message}`, { cause });
        error.evidence = { stage, elapsedMs: performance.now() - started, at: new Date().toISOString(), responder: responder.seen.slice(-30) };
        // Capture the short packet/request histories immediately, even if the
        // app's state API is the component that has stopped responding.
        Object.assign(error.evidence, Object.fromEntries(await Promise.all(Object.entries({
          state: server.api('state'),
          engineConnections: engineConnections(),
          gateway: harness.control('stats'),
          diagnostics: harness.control('diagnostics'),
          heartbeat: client('heartbeat', {}, 5000),
          requests: client('requests', {}, 5000),
          logs: Promise.all([
            ['server', path.join(dataDir, 'server.log')],
            ['engine', path.join(dataDir, 'engine.log')],
            ['gateway', path.join(dir, 'testisp', 'testisp.log')],
          ].map(async ([name, file]) => [name,
            await readFile(file, 'utf8').then((value) => value.split('\n').slice(-30).join('\n')).catch(String)])).then(Object.fromEntries),
        }).map(async ([name, promise]) => [name, await promise.catch((error) => ({ error: error.message }))]))));
        console.error(`CAP SETUP FAILURE ${JSON.stringify(error.evidence)}`);
        throw error;
      }
    };
    await prepare('pinning the client to the main line', () => pin(main.id));
    const mainHeld = await prepare('opening the main-line HTTPS flows', () => client('open', { count: 2, target: publicTarget }));
    await prepare('pinning the client to the secondary line', () => pinApp(clientExe, second.id));
    const secondHeld = await prepare('opening the controlled secondary-line HTTP flows',
      () => client('open', { count: 2, target: responder.virtual }));
    await prepare('waiting for all four setup flows in app state', () => counts(4));
    try {
      // Main has no stand-in, so its exception must preserve these sockets.
      await applied('lines/update', { id: second.id, strict: true }, (state) => state.lines.find((line) => line.id === second.id)?.strict);
      await server.api('lines/update', { id: main.id, cap: { bytes: 1, period: 'day' } });
      await server.api('lines/update', { id: second.id, cap: { bytes: 1, period: 'day' } });
      const blocked = await until(async () => {
        const state = await server.api('state');
        return state.lines.find((line) => line.id === second.id)?.blocked && state.lines;
      }, 'secondary cap applied');
      const closed = await until(async () => {
        const sockets = await client('status', { ids: secondHeld.map((item) => item.id) });
        return sockets.every((socket) => socket.closed) && sockets;
      }, 'flows admitted before the secondary cap closed');
      await client('refresh', { ids: mainHeld.map((item) => item.id) });
      assert.equal(blocked.find((line) => line.id === main.id).blocked, false);
      return { mainHeld, secondHeld, closed, blocked };
    } finally {
      await server.api('lines/update', { id: main.id, cap: null });
      await server.api('lines/update', { id: second.id, cap: null, strict: false });
      await until(async () => !(await server.api('state')).lines.some((line) => line.exhausted || line.blocked), 'caps cleared');
      await pin(second.id);
    }
  });
  await observe('exhausted secondary rejects a burst instead of hanging', 'baseline-defect', async () => {
    assert(rejectBaseline, 'Blocked: the Windows rejection baseline failed');
    await client('close');
    await client('open', { target: responder.virtual }); await client('close');
    await pinApp(udpRejectExe, second.id);
    const udpBefore = await udpReject(responder.virtual, 3);
    assert(udpBefore.every((sample) => sample.outcome === 'reply'), JSON.stringify(udpBefore));
    try {
      await server.api('lines/update', { id: main.id, cap: { bytes: 1, period: 'day' } });
      await server.api('lines/update', { id: second.id, cap: { bytes: 1, period: 'day' } });
      const blocked = await until(async () => { const state = await server.api('state'); return state.lines.find((line) => line.id === second.id)?.blocked && state.lines; }, 'both caps exhausted and secondary blocked', 30_000);
      const tcpLimitMs = Math.max(...rejectBaseline.tcp.map((sample) => sample.ms)) + 500;
      const udpLimitMs = Math.max(...rejectBaseline.udp.map((sample) => sample.ms)) + 500;
      const readiness = [];
      if (options.profile === 'baseline') {
        // 0.3.x reports a written rule file, not sing-box's asynchronous reload.
        // Observe an actual refusal before starting the measured burst. The
        // v1 state contract acknowledges an applied revision, so it gets no grace.
        await until(async () => {
          const [sample] = await client('reject', { target: responder.virtual, count: 1, timeout: tcpLimitMs });
          readiness.push(sample);
          assert(rejections.has(sample.outcome) && sample.ms <= tcpLimitMs,
            `Cap not applied yet: ${JSON.stringify({ tcpLimitMs, blocked, recent: readiness.slice(-5) })}`);
          return true;
        }, 'sing-box has applied the cap rejection rule', 30_000);
      }
      const beforeBurst = await harness.control('stats');
      const samples = await client('reject', { target: responder.virtual, timeout: tcpLimitMs });
      const udp = await udpReject(responder.virtual, 100, udpLimitMs);
      const afterBurst = await harness.control('stats');
      const burstEvidence = { blocked, tcpLimitMs, udpLimitMs, readiness, samples, udp, beforeBurst, afterBurst };
      assert(!samples.some((item) => item.outcome === 'connected'), `A capped app escaped the applied block: ${JSON.stringify(burstEvidence)}`);
      exactTraffic(beforeBurst, afterBurst, 0, `${responder.virtual.host}:${responder.virtual.http}`);
      exactTraffic(beforeBurst, afterBurst, 0, `${responder.virtual.host}:${responder.virtual.udp[0]}`);
      assert(!udp.some((item) => item.outcome === 'reply'), 'Capped UDP escaped the block');
      assert([...samples, ...udp].every((item) => item.outcome === 'timeout' || rejections.has(item.outcome)), `Unexpected probe failure: ${JSON.stringify({ samples, udp })}`);
      assert.equal(blocked.find((line) => line.id === main.id).blocked, false, 'Main line exception was removed');
      const mainException = await newTrafficOn(main, publicTarget);
      await server.api('lines/update', { id: main.id, cap: null });
      await server.api('lines/update', { id: second.id, cap: null });
      await until(async () => !(await server.api('state')).lines.some((line) => line.exhausted || line.blocked), 'caps cleared before recovery probes');
      await pin(second.id); await client('open', { target: responder.virtual }); await client('close');
      const beforeRecovery = await harness.control('stats');
      const udpAfter = await udpReject(responder.virtual, 3);
      assert(udpAfter.every((sample) => sample.outcome === 'reply'), JSON.stringify({ udpBefore, udp, udpAfter, state: await server.api('state'), beforeRecovery, afterRecovery: await harness.control('stats') }));
      const evidence = { rejectBaseline, ...burstEvidence, udpBefore, udpAfter, mainException };
      if (samples.some((item) => !rejections.has(item.outcome) || item.ms > tcpLimitMs)
        || udp.some((item) => !rejections.has(item.outcome) || item.ms > udpLimitMs)) {
        throw new BaselineDefect('Capped TCP/UDP did not fail fast; clearing the caps restored the same target', evidence);
      }
      return evidence;
    } finally {
      await server.api('lines/update', { id: main.id, cap: null });
      await server.api('lines/update', { id: second.id, cap: null });
      await until(async () => !(await server.api('state')).lines.some((line) => line.exhausted || line.blocked), 'caps cleared');
      await pin(second.id);
    }
  });
  await report.test('20 start/stop cycles clean up routes and present adapters', 'parity', async () => {
    const cycles = [], snapshots = [];
    for (let n = 1; n <= 20; n++) {
      const phases = {}, started = performance.now(), eventStart = serverOutput.events.length;
      try { await timedPhase(phases, 'routingOffMs', () => server.api('routing', { on: false })); }
      catch (error) {
        error.evidence = { cycle: n, phases, native: serverOutput.events.slice(eventStart) };
        throw error;
      }
      snapshots.push({ cycle: n, ...await timedPhase(phases, 'stoppedChecksMs', stoppedSnapshot) });
      await timedPhase(phases, 'routingOnMs', () => server.api('routing', { on: true }));
      await timedPhase(phases, 'routingReadyMs', () => server.on());
      rememberAppDevices(await timedPhase(phases, 'runningPnPCheckMs', pnpDevices));
      await timedPhase(phases, 'firstFlowMs', async () => {
        try { return await client('open', { target: responder.virtual }); } catch (error) {
          // ARM64 job 119224625441, cycle 14: the first request got no reply
          // for 8 s and nothing showed where it stopped. The check is unchanged.
          error.evidence = { cycle: n, phases, native: serverOutput.events.slice(eventStart), ...await cycleFailureCapture() };
          throw error;
        }
      });
      await timedPhase(phases, 'clientCloseMs', () => client('close'));
      const result = { cycle: n, totalMs: performance.now() - started, phases, stoppedChecks: snapshots.at(-1).phases,
        native: serverOutput.events.slice(eventStart) };
      cycles.push(result); console.log(`WINDOWS CYCLE ${JSON.stringify(result)}`);
    }
    const devices = [...new Map(snapshots.flatMap((s) => s.pnp).map((device) => [device.instanceId, device])).values()];
    await recordOrphanPnP('PnP cleanup across 20 normal routing stops', 'baseline-defect', { snapshots }, devices);
    return cycles;
  });
  await report.test('engine crash with automatic restart', 'parity', async () => {
    const engine = await verifyEngineProcess(options, dataDir);
    try { process.kill(engine.pid, 'SIGKILL'); } catch (error) { if (error.code !== 'ESRCH') throw error; }
    const restarted = await until(async () => {
      const current = await verifyEngineProcess(options, dataDir);
      return current.pid !== engine.pid && current;
    }, 'engine automatic restart', 90_000);
    await server.on();
    const response = await client('open', { target: responder.virtual }); await client('close');
    const devices = await pnpDevices();
    rememberAppDevices(devices);
    await recordOrphanPnP('PnP cleanup after automatic engine restart', 'parity', { engine, restarted }, devices.filter((device) => !device.present));
    return { engine, restarted, response };
  });
  if (options.profile === 'v1') {
    await report.test('engine crash without restart removes its observed phantom through the journal without loading Wintun', 'parity', async () => {
      const engine = await verifyEngineProcess(options, dataDir);
      const before = await pnpDevices();
      assert(before.some((device) => device.present && appDeviceIDs.has(device.instanceId)), 'Crash cleanup needs the live owned device first');
      server.child.kill('SIGKILL');
      await until(() => server.child.exitCode !== null || server.child.signalCode !== null, 'controller stopped before engine crash');
      try { process.kill(engine.pid, 0); }
      catch (error) { assert.fail(`Controller death killed the independent engine before its lease expired: ${error.message}`); }
      process.kill(engine.pid, 'SIGKILL');
      await until(() => {
        try { process.kill(engine.pid, 0); return false; }
        catch (error) { if (error.code !== 'ESRCH') throw error; return true; }
      }, 'crashed engine exited');
      const crashed = await stoppedSnapshot({ crashed: true });
      assert(crashed.pnp.some((device) => appDeviceIDs.has(device.instanceId) && !device.present),
        `No owned phantom existed before recovery; cleanup cannot receive credit: ${JSON.stringify(crashed)}`);
      const direct = await harness.probe();
      const recoveryExe = path.resolve('dist/windows-test/recovery/netswitch-engine.exe');
      await assert.rejects(readFile(path.join(path.dirname(recoveryExe), 'wintun.dll')), { code: 'ENOENT' });
      const binary = await identity(recoveryExe);
      const recovery = await run(recoveryExe, ['cleanup', '--state-dir', path.join(dataDir, 'native-state')]);
      const cleaned = await clean();
      // Repeat the real recovery operation; it must not require another
      // adapter or erase another program's state.
      await run(recoveryExe, ['cleanup', '--state-dir', path.join(dataDir, 'native-state')]);
      await start();
      return { engine, before, crashed, direct, binary, recovery, cleaned };
    });
  }
  if (options.profile === 'v1') {
    await report.test('a restarted controller reattaches within the lease without closing held flows', 'parity', async () => {
      await client('close');
      await pin(second.id);
      const held = await client('open', { count: 2, target: responder.virtual });
      const before = await server.api('engine-command', { method: 'hello' });
      const processBefore = await verifyEngineProcess(options, dataDir);
      server.child.kill('SIGKILL');
      await until(() => server.child.exitCode !== null || server.child.signalCode !== null, 'old controller exits');
      await start();
      const processAfter = await verifyEngineProcess(options, dataDir);
      const after = await server.api('engine-command', { method: 'hello' });
      assert.equal(processAfter.pid, processBefore.pid, 'Reattach restarted the live engine');
      assert.equal(after.engineInstanceId, before.engineInstanceId);
      assert(after.epoch > before.epoch, 'The engine did not issue a newer attach epoch');
      await assert.rejects(server.api('engine-command', { method: 'renew',
        fields: { engineInstanceId: before.engineInstanceId, epoch: before.epoch } }), /fenced/);
      const refreshed = await client('refresh', { ids: held.map((item) => item.id) });
      await client('close');
      return { before, after, processBefore, processAfter, held, refreshed };
    });
  }
  await report.test('crash without a restart restores direct connectivity', 'parity', async () => {
    const engine = await verifyEngineProcess(options, dataDir);
    server.child.kill('SIGKILL');
    // Engine exit is independently observed. Never confuse killing the whole
    // process tree with the app cleaning up after one component crashes.
    await until(() => server.child.exitCode !== null || server.child.signalCode !== null, 'control process death');
    const deathStarted = performance.now();
    const exited = await until(() => {
      try { process.kill(engine.pid, 0); return false; }
      catch (error) { if (error.code !== 'ESRCH') throw error; return { pid: engine.pid, exitedWithoutHarnessKill: true }; }
    }, 'engine exits on its own after control process death', options.profile === 'v1' ? 35_000 : 30_000);
    exited.observedAfterMs = performance.now() - deathStarted;
    exited.old30SecondCheckWouldPass = exited.observedAfterMs <= 30_000;
    const state = await stoppedSnapshot();
    await recordOrphanPnP('PnP cleanup immediately after control-process crash', 'baseline-defect', state.state, state.pnp);
    const direct = await harness.probe();
    await start();
    const response = await client('open', { target: responder.virtual }); await client('close');
    return { exited, state, direct, response };
  });
  if (options.profile === 'v1') {
    await report.test('OS port limit refuses cleanly, preserves flows and recovers within the 512 MiB budget', 'parity', async () => {
      await client('close');
      const { capacity } = await import('./capacity.mjs');
      return capacity({ server, harness, directory: dir, line: second.id, stopHeld: async (held) => {
        assert(held.tcp > 0 && held.udp > 0, 'Loaded stop needs independently reconciled TCP flows and UDP sessions');
        console.log(`WINDOWS LOADED STOP BEGIN ${JSON.stringify(held)}`);
        const began = performance.now();
        await server.api('routing', { on: false });
        const stopMs = performance.now() - began;
        assert(stopMs < 20_000, `Loaded stop exceeded service budget: ${stopMs} ms`);
        const cleanup = await stoppedSnapshot();
        const direct = await harness.probe();
        const evidence = { ...held, stopMs, cleanup, direct };
        console.log(`WINDOWS LOADED STOP ${JSON.stringify(evidence)}`);
        return evidence;
      } });
    });
    report.pendingMilestone('service lifecycle and hung worker', 2, 'The engine process is real; SCM installation, recovery actions and Control worker jobs are the separate lifecycle milestone.');
    report.pendingMilestone('installer migration from 0.3.0/0.3.1, update rollback and uninstall', 5, 'Release remains blocked on the installer milestone. Existing installer smoke tests remain required.');
  } else {
    report.deferred('service lifecycle, lease reattach and lapse, hung worker', 2, 'Today’s Node app has no service/lease/worker IPC contract.');
    report.deferred('installer migration from 0.3.0/0.3.1, update rollback and uninstall', 5, 'The 1.0 service layout and installer do not exist yet. Existing installer smoke tests remain required.');
    report.deferred('freeze: sequence wrap, stale SYN/data/RST, final ACK loss, timestamps off, reordered TUN queues', 3, 'These require the engine’s in-memory link endpoint; Winsock does not expose the app-side TCP sequence or queue injection. Socket reuse tests above run against today’s app.');
  }
} catch (error) {
  console.error(error); process.exitCode = 1;
  if (!report.results.some((result) => result.status === 'fail')) report.results.push({ name: 'acceptance setup or teardown', label: server ? 'parity' : 'harness-baseline', status: 'fail', error: error.stack });
} finally {
  if (restoreDNS) try { await network('dns-restore', dnsAdapter); } catch (error) { console.error(error); process.exitCode = 1; }
  if (worker?.exitCode === null && worker.connected) worker.disconnect();
  if (quicServer?.exitCode === null) quicServer.kill();
  if (server?.child.exitCode === null) {
    const began = performance.now(), eventStart = serverOutput.events.length;
    let completed = false;
    try { await server.quit(); completed = true; } catch (error) { console.error(error); process.exitCode = 1; }
    finally { console.log(`WINDOWS FINAL QUIT ${JSON.stringify({ elapsedMs: performance.now() - began, completed,
      native: serverOutput.events.slice(eventStart).filter(event => event.operation === 'stop') })}`); }
  }
  // Check before TestISP's Wintun shutdown can erase an orphan. Only the same
  // non-present IDs observed while our engine was running may use this baseline
  // exemption. The normal 0.3.x stop also terminates its child on Windows.
  let finalPnP = [], finalPnPError;
  try { if (server) finalPnP = await pnpDevices(); } catch (error) { finalPnPError = error; }
  const knownOrphans = finalPnP.length > 0 && finalPnP.every((device) => !device.present && appDeviceIDs.has(device.instanceId));
  await observe('final NetSwitch adapter, route and firewall cleanup', server ? 'baseline-defect' : 'harness-baseline', async () => {
    if (finalPnPError) throw finalPnPError;
    if (!knownOrphans) return clean();
    const state = await network('state');
    assert(Object.values(state).every((list) => list.length === 0), JSON.stringify(state));
    throw new BaselineDefect('An owned non-present Wintun device remains before TestISP shuts down', { state, pnp: finalPnP });
  });
  // Record the actual cleanup result first. Only then end a server this harness
  // started if quit failed, so its open handles cannot hide the failure behind
  // the job timeout or keep routing through TestISP while TestISP shuts down.
  if (server?.child.exitCode === null && server.child.signalCode === null) {
    console.error('Emergency cleanup of the test-owned server after failed quit; the failed result is preserved.');
    process.exitCode = 1;
    try {
      server.child.kill('SIGKILL');
      await until(() => server.child.exitCode !== null || server.child.signalCode !== null, 'test-owned server emergency cleanup', 30_000);
    } catch (error) { console.error(error); }
  }
  if (harness) try { await harness.close(); } catch (error) { console.error(error); process.exitCode = 1; }
  try { await targetFirewall('clean'); } catch (error) { console.error(error); process.exitCode = 1; }
  if (responder) { await writeFile(path.join(dir, 'target-observations.json'), JSON.stringify(responder.seen, null, 2)); await responder.close(); }
  if (tlsResponder) { await writeFile(path.join(dir, 'tls-observations.json'), JSON.stringify(tlsResponder.seen, null, 2)); await tlsResponder.close(); }
  output.end();
  await report.save(path.join(dir, 'report.json'));
  if (unrelatedFirewall) await unrelatedFirewall.close().catch((error) => { console.error(error); process.exitCode = 1; });
  if (inspection) await inspection.close().catch((error) => { console.error(error); process.exitCode = 1; });
  if (options.profile === 'v1' && report.results.some((result) => ['deferred', 'blocked', 'pending-shared-hook'].includes(result.status))) {
    console.error('The v1 profile cannot pass while required gates are deferred, blocked or pending the shared hook.'); process.exitCode = 1;
  }
}
