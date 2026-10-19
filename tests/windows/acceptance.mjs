import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { createWriteStream } from 'node:fs';
import { copyFile, mkdir, readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import { launchOptions, recordLaunch, startServer, verifyEngineProcess } from './launch.mjs';
import { BaselineDefect, Report } from './report.mjs';
import { targets } from './targets.mjs';
import { hostedOnly, identity, run, startHarness, until } from './testisp/harness.mjs';

hostedOnly();
const options = launchOptions();
assert(['baseline', 'v1'].includes(options.profile), 'Use --profile baseline or v1');
const dir = path.resolve('dist/windows-acceptance');
const dataDir = path.join(dir, 'app');
await mkdir(dataDir, { recursive: true });
const report = new Report(options.profile);
const output = createWriteStream(path.join(dir, 'server-output.log'));
const clientExe = path.join(dir, 'acceptance-app.exe');
await copyFile(process.execPath, clientExe);
let harness, responder, server, worker, dnsAdapter, quicServer, quic, restoreDNS = false;
const quicExe = path.resolve('dist/windows-test/quicprobe.exe');
let main, second;
const pending = new Map();
let serial = 0;

function client(command, args = {}, timeout = 120_000) {
  return new Promise((resolve, reject) => {
    const id = ++serial;
    const timer = setTimeout(() => { pending.delete(id); reject(new Error(`${command}: client deadline`)); }, timeout);
    pending.set(id, { resolve, reject, timer }); worker.send({ id, command, ...args });
  });
}

async function network(action, adapter) {
  const result = await run('powershell.exe', ['-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', path.resolve('scripts/tun-test-network.ps1'), '-Action', action], {
    env: { NETSWITCH_TEST_ADAPTER: String(adapter?.index ?? ''), NETSWITCH_TEST_STATIC_DNS: adapter?.staticDns ?? '' },
  });
  return JSON.parse(result.stdout.replace(/^\uFEFF/, ''));
}

async function clean() {
  return until(async () => { const state = await network('state'); assert(Object.values(state).every((list) => list.length === 0), JSON.stringify(state)); return state; }, 'no NetSwitch adapter, route or firewall leftovers', 20_000);
}

async function pin(line) {
  await client('close');
  await until(async () => {
    const state = await server.api('state');
    const app = state.apps.find((item) => item.path.toLowerCase() === clientExe.toLowerCase());
    return !app || Object.values(app.connections).every((count) => count === 0);
  }, 'previous test-app connections closed', 25_000);
  await server.api('app-line', { path: clientExe, line });
  await delay(500);
}

async function counts(total) {
  return until(async () => {
    const state = await server.api('state');
    const app = state.apps.find((item) => item.path.toLowerCase() === clientExe.toLowerCase());
    if (!app || Object.values(app.connections).reduce((sum, n) => sum + n, 0) < total) return null;
    return app.connections;
  }, `${total} real test-app flows in app state`, 25_000);
}

async function newPublicOn(line, count = 3) {
  await pin(line.id);
  const before = await harness.control('stats');
  const opened = await client('open', { count });
  const byLine = await counts(count);
  assert.equal(byLine[line.id], count, JSON.stringify(byLine));
  assert.equal(Object.values(byLine).reduce((sum, n) => sum+n, 0), count, 'Old sockets still counted');
  const after = await harness.control('stats');
  if (line.id === second.id) assert(after.testisp.connections >= before.testisp.connections + count, 'No TestISP wire evidence');
  return { opened, byLine, before, after };
}

async function publicBaseline() { return { direct: await harness.probe(harness.uplink), virtual: await harness.probe(harness.testisp) }; }

async function targetFirewall(action) {
  return run('powershell.exe', ['-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', path.resolve('tests/windows/target-network.ps1'), '-Action', action], {
    env: { ACCEPTANCE_CLIENT: clientExe, ACCEPTANCE_GATEWAY: path.resolve('dist/windows-test/testisp.exe'), ACCEPTANCE_TARGET: harness?.uplink.address ?? '',
      ACCEPTANCE_UPLINK: String(harness?.uplink.index ?? ''), ACCEPTANCE_TESTISP: String(harness?.testisp.index ?? '') },
  });
}

async function ping(host, source, size = 32, df = false) {
  const args = [host.includes(':') ? '-6' : '-4', '-n', '1', '-w', '3000', '-l', String(size)];
  if (source && host.includes(':')) args.push('-S', source);
  if (df) args.push('-f');
  args.push(host);
  const result = await run('ping.exe', args, { timeout: 10_000 });
  assert.match(result.stdout, /(?:time[=<]|TTL=)/i, 'Ping had no actual echo reply');
  return result.stdout;
}

async function quicProbe(host, source, index) {
  const port = quic.address.split(':').at(-1);
  const args = ['--address', `${host}:${port}`, '--certificate', quic.certificate];
  if (source) args.push('--source', source);
  if (index) args.push('--interface', String(index));
  const result = await run(quicExe, args, { timeout: 20_000 });
  return JSON.parse(result.stdout);
}

async function start() {
  server = await startServer(options, dataDir, (chunk) => output.write(chunk));
  const state = await server.on();
  await verifyEngineProcess(options, dataDir);
  return state;
}

try {
  await recordLaunch(options, path.join(dir, 'executables.json'));
  await report.test('clean before start', 'parity', clean);
  dnsAdapter = await network('inspect');
  harness = await startHarness(path.join(dir, 'testisp'));
  responder = await targets(harness.uplink.address);
  await targetFirewall('allow');
  await targetFirewall('ipv6');
  await writeFile(path.join(dir, 'quic-executable.json'), JSON.stringify(await identity(quicExe), null, 2));
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
  await report.test('both public egress baselines', 'parity', publicBaseline);
  await report.test('real QUIC v1 baseline on both line addresses', 'parity', async () => ({
    direct: await quicProbe(harness.uplink.address, harness.uplink.address, harness.uplink.index),
    virtual: await quicProbe(responder.virtual.host, harness.testisp.address, harness.testisp.index),
  }));
  await report.test('controlled HTTP reachable through both line addresses', 'parity', async () => {
    const direct = await client('open', { target: responder.direct }); await client('close');
    const before = await harness.control('stats');
    const virtual = await client('open', { target: { ...responder.virtual, source: harness.testisp.address } }); await client('close');
    const after = await harness.control('stats');
    assert(after.testisp.connections > before.testisp.connections);
    return { direct, virtual, before, after };
  });
  for (const size of [64, 1200, 1800, 8192]) {
    await report.test(`controlled UDP baseline ${size} bytes on both lines`, 'parity', async () => ({
      direct: await client('udp', { target: responder.direct, size }),
      virtual: await client('udp', { target: responder.virtual, size, localAddress: harness.testisp.address }),
    }));
  }
  await report.test('gateway preserves STUN mapping before engine starts', 'parity', async () => {
    const result = await client('udp', { target: responder.virtual, stun: true, localAddress: harness.testisp.address });
    assert.equal(new Set(result.mappings.map((item) => item.port)).size, 1, JSON.stringify(result));
    assert(result.unsolicited, `The gateway lost the third, uncontacted STUN sender: ${JSON.stringify({ result, stats: await harness.control('stats'), target: responder.seen.slice(-5) })}`);
    return result;
  });
  const directReuse = await report.test('controlled port reuse baseline', 'parity', async () => {
    const samples = await client('reuse', { target: { ...responder.virtual, source: harness.testisp.address }, count: 20 });
    assert.equal(samples.length, 20); assert(samples.every((sample) => sample.outcome === 'closed'), JSON.stringify(samples));
    return samples;
  });
  await report.test('controlled ICMP v4/v6 baselines', 'parity', async () => ({
    v4: await ping(responder.virtual.host, harness.testisp.address),
    v6: await ping('2001:db8:198::2', '2001:db8:19::1'),
  }));
  const ipv6Target = { ...responder.virtual, host: '2001:db8:198::2' };
  await report.test('controlled IPv6 TCP and UDP baselines', 'parity', async () => {
    const tcp = await client('open', { target: { ...ipv6Target, source: '2001:db8:19::1' } }); await client('close');
    const udp = await client('udp', { target: ipv6Target, localAddress: '2001:db8:19::1' });
    return { tcp, udp };
  });
  await writeFile(path.join(dataDir, 'settings.json'), JSON.stringify({ checkForUpdates: false }));
  await targetFirewall('capture');
  const initial = await start();
  main = initial.lines[0];
  assert.equal(main.alias, harness.uplink.alias, 'Default line is not the real uplink');
  await server.api('lines/add', { alias: 'TestISP' });
  const state = await server.on();
  second = state.lines.find((line) => line.alias === 'TestISP');
  assert(second && state.lines.length === 2, JSON.stringify(state.lines));
  await report.test('pins cross two actual interfaces', 'parity', async () => ({ direct: await newPublicOn(main), virtual: await newPublicOn(second) }));
  await report.test('new pin leaves old connections alive', 'parity', async () => {
    const original = await client('open', { count: 3 });
    await server.api('app-line', { path: clientExe, line: main.id }); await delay(500);
    const next = await client('open', { count: 3 });
    await client('refresh', { ids: original.map((item) => item.id) });
    const byLine = await counts(9);
    assert(byLine[second.id] >= 6 && byLine[main.id] === 3, JSON.stringify(byLine));
    return { original, next, byLine };
  });
  await client('close'); await delay(2000);
  await report.test('combining distributes real traffic over both interfaces', 'parity', async () => {
    await pin(null);
    await server.api('combine', { on: true, mode: 'manual', weights: { [main.id]: 1, [second.id]: 1 } }); await delay(500);
    const before = await harness.control('stats');
    await client('open', { count: 40 });
    const byLine = await counts(40);
    assert(byLine[main.id] >= 10 && byLine[second.id] >= 10, JSON.stringify(byLine));
    const after = await harness.control('stats');
    assert(after.testisp.connections >= before.testisp.connections + byLine[second.id]);
    await client('close');
    await server.api('combine', { on: false });
    return { byLine, before, after };
  });
  await report.test('default-route loss fails over and restoration fails back', 'parity', async () => {
    await pin(second.id);
    await harness.network('withdraw');
    const failedOver = await until(async () => {
      const state = await server.api('state');
      return state.lines.find((line) => line.id === second.id)?.target === main.id && state.lines;
    }, 'TestISP failover', 60_000);
    await client('open', { count: 3 });
    const byLine = await counts(3); assert.equal(byLine[main.id], 3);
    await harness.network('restore');
    const failedBack = await until(async () => {
      const state = await server.api('state');
      return state.lines.find((line) => line.id === second.id)?.target === second.id && state.lines;
    }, 'TestISP failback', 90_000);
    await client('close'); await delay(2000);
    return { failedOver, byLine, failedBack, traffic: await newPublicOn(second) };
  });
  await pin(second.id);
  await report.test('controlled HTTP crosses the app TUN and TestISP', 'parity', async () => {
    const before = await harness.control('stats');
    const response = await client('open', { target: responder.virtual });
    const byLine = await counts(1); assert.equal(byLine[second.id], 1);
    const after = await harness.control('stats'); assert(after.testisp.connections > before.testisp.connections);
    await client('close'); return { response, byLine, before, after };
  });
  for (const size of [64, 1200, 1800, 8192]) {
    await report.test(`UDP payload and fragmentation through TUN: ${size} bytes`, 'parity', () => client('udp', { target: responder.virtual, size }));
  }
  await report.test('STUN two-server mapping through TUN', 'parity', async () => {
    const result = await client('udp', { target: responder.virtual, stun: true });
    assert.equal(new Set(result.mappings.map((item) => item.port)).size, 1, JSON.stringify(result));
    assert(result.unsolicited, 'The app lost the third, uncontacted STUN sender');
    return result;
  });
  await report.test('real QUIC v1 through TUN has the right payload hash', 'parity', async () => {
    await server.api('app-line', { path: quicExe, line: second.id }); await delay(500);
    const before = await harness.control('stats');
    const response = await quicProbe(responder.virtual.host);
    const after = await harness.control('stats');
    assert(after.testisp.bytesIn > before.testisp.bytesIn && after.testisp.bytesOut > before.testisp.bytesOut);
    return { response, before, after };
  });
  await report.test('controlled IPv6 TCP and UDP through TUN', 'parity', async () => {
    assert.equal((await server.api('state')).routing.ipv6, true, 'IPv6 capture was not enabled');
    const tcp = await client('open', { target: ipv6Target });
    const byLine = await counts(1); assert(byLine[second.id] >= 1); await client('close');
    const udp = await client('udp', { target: ipv6Target }); return { tcp, udp, byLine };
  });
  await report.test('ICMP v4/v6 and 1400-byte MTU probes through TUN', 'parity', async () => {
    await server.api('lines/order', { ids: [second.id, main.id] }); await server.on();
    const before = await harness.control('stats');
    const result = { v4: await ping(responder.virtual.host), v6: await ping(ipv6Target.host),
      mtu4: await ping(responder.virtual.host, undefined, 1400, true), mtu6: await ping(ipv6Target.host, undefined, 1400) };
    const after = await harness.control('stats');
    assert(after.testisp.packetsIn >= before.testisp.packetsIn + 4, 'Echo replies did not reach the controlled path');
    await server.api('lines/order', { ids: [main.id, second.id] }); await server.on();
    return { result, before, after };
  });
  for (const gap of [0, 10, 100, 500]) {
    await report.test(`freeze gate: ${gap} ms port reuse`, 'baseline-defect', async () => {
      const samples = await client('reuse', { target: responder.virtual, count: gap ? 10 : 1000, gap });
      const failure = samples.find((sample) => sample.outcome !== 'closed' || sample.ms > 100 + gap);
      if (failure?.outcome === 'timeout' && samples[0].outcome === 'closed') {
        let recovery;
        if (gap === 0) {
          const started = performance.now();
          await delay(62_000);
          recovery = await client('reuse', { target: responder.virtual, count: 1, reusePort: failure.port });
          assert.equal(recovery[0].outcome, 'closed', 'Port did not recover after the expected TIME_WAIT interval');
          recovery = { afterMs: performance.now() - started, samples: recovery };
        }
        throw new BaselineDefect('A reusable app port stalls behind the TUN after a successful passive close', { samples, directReuse, recovery });
      }
      assert(!failure, JSON.stringify(failure));
      return { count: samples.length, maxMs: Math.max(...samples.map((sample) => sample.ms)) };
    });
  }
  const large = await report.test('100 MB TCP transfer with a payload hash', 'parity', async () => {
    const samples = await client('reuse', { target: responder.virtual, count: 1, length: 100_000_000 });
    assert.equal(samples[0]?.outcome, 'closed', JSON.stringify(samples)); return samples;
  });
  await report.test('freeze gate: reuse after 100 MB transfer', 'baseline-defect', async () => {
    const samples = await client('reuse', { target: responder.virtual, count: 1, reusePort: large[0].port });
    if (samples[0].outcome === 'timeout') throw new BaselineDefect('Port stalls after a verified 100 MB transfer', samples);
    assert.equal(samples[0].outcome, 'closed'); return samples;
  });
  await report.test('DNS change leaves held sockets alive', 'baseline-defect', async () => {
    await client('close');
    const held = await client('open', { count: 5, target: responder.virtual });
    restoreDNS = true;
    const changed = await network('dns-change', dnsAdapter);
    assert.notDeepEqual(changed, dnsAdapter.dns);
    await delay(3000);
    let lost;
    try { await client('refresh', { ids: held.map((item) => item.id) }); } catch (error) { lost = error.message; }
    const after = await server.api('state'); assert.equal(after.routing.status, 'on');
    await network('dns-restore', dnsAdapter); restoreDNS = false;
    await client('close');
    await client('open', { target: responder.virtual }); await client('close');
    if (lost) throw new BaselineDefect('DNS change closed existing connections while routing remained on', { lost, changed, after: after.routing });
    return { changed, held };
  });
  await report.test('exhausted secondary rejects a burst instead of hanging', 'baseline-defect', async () => {
    await client('close');
    await server.api('lines/update', { id: main.id, cap: { bytes: 1, period: 'day' } });
    await server.api('lines/update', { id: second.id, cap: { bytes: 1, period: 'day' } });
    const blocked = await until(async () => { const state = await server.api('state'); return state.lines.find((line) => line.id === second.id)?.blocked && state.lines; }, 'both caps exhausted and secondary blocked', 30_000);
    await delay(500);
    const samples = await client('reject', { target: responder.virtual });
    assert(!samples.some((item) => item.outcome === 'connected'), 'A capped app escaped the block');
    assert(samples.some((item) => ['ECONNRESET', 'ECONNREFUSED'].includes(item.outcome)), 'No actual rejection before the burst');
    await server.api('lines/update', { id: main.id, cap: null });
    await server.api('lines/update', { id: second.id, cap: null });
    await delay(500); await client('open', { target: responder.virtual }); await client('close');
    if (samples.some((item) => item.outcome === 'timeout')) throw new BaselineDefect('Repeated cap rejects become silent drops without no_drop', { blocked, samples });
    return { blocked, samples };
  });
  await report.test('20 start/stop cycles clean up routes and adapters', 'parity', async () => {
    const cycles = [];
    for (let n = 1; n <= 20; n++) {
      await server.api('routing', { on: false }); await clean();
      await server.api('routing', { on: true }); await server.on();
      await client('open', { target: responder.virtual }); await client('close');
      cycles.push(n); console.log(`cycle ${n}/20`);
    }
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
    return { engine, restarted, response };
  });
  await report.test('crash without a restart restores direct connectivity', 'parity', async () => {
    const engine = await verifyEngineProcess(options, dataDir);
    server.child.kill('SIGKILL');
    // Engine exit is independently observed. Never confuse killing the whole
    // process tree with the app cleaning up after one component crashes.
    await until(() => server.child.exitCode !== null, 'control process death');
    try { process.kill(engine.pid, 'SIGKILL'); } catch (error) { if (error.code !== 'ESRCH') throw error; }
    const state = await clean();
    const direct = await harness.probe(harness.uplink);
    await start();
    const response = await client('open', { target: responder.virtual }); await client('close');
    return { state, direct, response };
  });
  report.deferred('service lifecycle, lease reattach and lapse, hung worker', 2, 'Today’s Node app has no service/lease/worker IPC contract.');
  report.deferred('installer migration from 0.3.0/0.3.1, update rollback and uninstall', 5, 'The 1.0 service layout and installer do not exist yet. Existing installer smoke tests remain required.');
  report.deferred('freeze: sequence wrap, stale SYN/data/RST, final ACK loss, timestamps off, reordered TUN queues', 3, 'These require the engine’s in-memory link endpoint; Winsock does not expose the app-side TCP sequence or queue injection. Socket reuse tests above run against today’s app.');
} catch (error) {
  console.error(error); process.exitCode = 1;
  if (!report.results.some((result) => result.status === 'fail')) report.results.push({ name: 'acceptance setup or teardown', label: 'parity', status: 'fail', error: error.stack });
} finally {
  if (restoreDNS) try { await network('dns-restore', dnsAdapter); } catch (error) { console.error(error); process.exitCode = 1; }
  if (worker?.exitCode === null && worker.connected) worker.disconnect();
  if (quicServer?.exitCode === null) quicServer.kill();
  if (server?.child.exitCode === null) try { await server.quit(); } catch (error) { console.error(error); process.exitCode = 1; }
  if (harness) try { await harness.close(); } catch (error) { console.error(error); process.exitCode = 1; }
  try { await targetFirewall('clean'); } catch (error) { console.error(error); process.exitCode = 1; }
  if (responder) { await writeFile(path.join(dir, 'target-observations.json'), JSON.stringify(responder.seen, null, 2)); await responder.close(); }
  output.end();
  await report.save(path.join(dir, 'report.json'));
}
