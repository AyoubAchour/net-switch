// Test-only controller for the 1.0 engine acceptance profile. No HTTP engine,
// service manager or legacy sing-box adapter is involved. The public traffic
// assertions remain in acceptance.mjs; this translates their control actions
// into full revisions, closure intents and lease commands.
import assert from 'node:assert/strict';
import { spawn, execFile } from 'node:child_process';
import { createHash, randomUUID } from 'node:crypto';
import { once } from 'node:events';
import { readFile, writeFile } from 'node:fs/promises';
import net from 'node:net';
import path from 'node:path';
import { promisify } from 'node:util';
import { setTimeout as delay } from 'node:timers/promises';
import { hostedOnly } from './testisp/harness.mjs';

hostedOnly();
const exec = promisify(execFile);
const [exe, directory] = process.argv.slice(2);
assert(exe && directory && process.send, 'Use the acceptance launcher');
const pipeName = String.raw`\\.\pipe\ProtectedPrefix\Administrators\NetSwitch\engine`;
const stateDir = path.join(directory, 'native-state');
const settingsFile = path.join(directory, 'engine-driver.json');
let engine, pipe, epoch = 0, instance = '', serial = 0, stopping = false, ready = false;
let saved, adapters, latest, healthBusy = false, reconnecting;
let fatalError;
let heapProfile;
const failures = [];
const pending = new Map();
let queue = Promise.resolve();
function serially(fn) {
  const next = queue.then(fn);
  queue = next.catch(() => {});
  return next;
}
const appKey = (p) => p.toLowerCase().replaceAll('/', '\\').split('\\').map((s, i, a) =>
  i < a.length - 1 && /^(?:app-|v)?[0-9]+(?:\.[0-9]+)+$/i.test(s) ? s.replace(/[0-9]+(?:\.[0-9]+)+/, '*') : s).join('\\');
const sorted = (o) => Object.fromEntries(Object.entries(o).sort(([a], [b]) => a < b ? -1 : a > b ? 1 : 0));
async function persist() { await writeFile(settingsFile, JSON.stringify(saved)); }

function command(method, fields = {}, timeout = 30_000) {
  assert(pipe && !pipe.destroyed, 'Engine pipe is disconnected');
  const id = String(++serial);
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => { pending.delete(id); reject(new Error(`${method}: engine deadline`)); }, timeout);
    pending.set(id, { resolve, reject, timer });
    pipe.write(JSON.stringify({ id, method, engineInstanceId: instance, epoch, ...fields }) + '\n');
  });
}
async function connect() {
  const deadline = Date.now() + 30_000;
  for (;;) {
    try {
      pipe = await new Promise((resolve, reject) => {
        const candidate = net.connect(pipeName);
        candidate.once('error', reject);
        candidate.once('connect', () => { candidate.removeListener('error', reject); resolve(candidate); });
      });
      break;
    } catch (error) {
      if (engine?.exitCode !== null && engine?.exitCode !== undefined) throw new Error(`Engine exited ${engine.exitCode} before opening its pipe`);
      if (Date.now() >= deadline) throw error;
      await delay(10);
    }
  }
  let buffer = '';
  pipe.on('data', (chunk) => {
    buffer += chunk;
    assert(buffer.length <= 2 << 20, 'Engine reply exceeds the protocol budget');
    for (;;) {
      const end = buffer.indexOf('\n');
      if (end < 0) break;
      const reply = JSON.parse(buffer.slice(0, end));
      buffer = buffer.slice(end + 1);
      if (reply.event) { console.log(`ENGINE EVENT ${JSON.stringify(reply)}`); continue; }
      const waiter = pending.get(reply.id);
      if (!waiter) continue;
      pending.delete(reply.id); clearTimeout(waiter.timer);
      if (reply.error) waiter.reject(new Error(reply.error)); else waiter.resolve(reply.result);
    }
  });
  pipe.on('error', (error) => console.error(`engine pipe: ${error.message}`));
  pipe.on('close', () => {
    ready = false;
    for (const { reject, timer } of pending.values()) { clearTimeout(timer); reject(new Error('Engine disconnected')); }
    pending.clear();
  });
  epoch = 0; instance = '';
  const hello = await command('hello');
  instance = hello.engineInstanceId;
  const attached = await command('attach');
  epoch = attached.epoch;
  console.log(`ENGINE ATTACH ${JSON.stringify({ instance, epoch, loaded: hello.appliedRevision })}`);
}
async function launch() {
  // libuv assigns ordinary Windows children to a kill-on-parent-close job.
  // The engine owns its lease and must survive this test controller's death.
  const env = { ...process.env };
  // Build concurrency is capped by CI; the process under measurement uses
  // Go's production processor default and the engine's unchanged limits.
  delete env.GOMAXPROCS;
  heapProfile = undefined;
  if (env.NETSWITCH_ENGINE_HEAP_CAPTURE === '1') {
    const nonce = randomUUID().replaceAll('-', '');
    heapProfile = { nonce, directory: path.join(directory, `heap-${nonce}`), sequence: 0 };
    env.NETSWITCH_ENGINE_HEAP_DIR = heapProfile.directory;
    env.NETSWITCH_ENGINE_HEAP_NONCE = nonce;
  }
  engine = spawn(exe, ['run', '--standalone-admin', '--state-dir', stateDir], {
    detached: true, windowsHide: true, stdio: ['ignore', 'inherit', 'inherit'], env,
  });
  const current = engine;
  engine.on('error', (error) => console.error(error));
  engine.on('exit', (code, signal) => {
    console.log(`ENGINE EXIT ${JSON.stringify({ pid: current.pid, code, signal, stopping })}`);
    if (current !== engine || stopping || !saved.on) return;
    ready = false;
    failures.push(Date.now());
    while (failures[0] < Date.now() - 600_000) failures.shift();
    if (failures.length >= 5) {
      fatalError = 'Engine failed five times in ten minutes; normal routing remains restored';
      console.error(fatalError);
      return;
    }
    reconnecting = serially(async () => {
      await delay([1000, 2000, 5000, 30_000][Math.min(failures.length - 1, 3)]);
      await launch();
    });
    reconnecting.catch((error) => { console.error(error); process.exitCode = 1; });
  });
  await writeFile(path.join(directory, 'engine.pid'), String(engine.pid));
  await connect();
  await apply('start');
  ready = true;
}

function policy() {
  const lines = saved.lines;
  for (const line of lines) {
    line.exhausted = Boolean(line.cap && (latest?.totals?.lines?.[line.id]?.up ?? 0) + (latest?.totals?.lines?.[line.id]?.down ?? 0) >= line.cap.bytes);
  }
  const open = (l) => l.up && !l.strict && !l.exhausted;
  for (const line of lines) {
    line.target = line.up && !line.exhausted ? line.id : lines.find((other) => other.id !== line.id && open(other))?.id ?? line.id;
    line.blocked = line.id !== lines[0].id && line.exhausted && line.target === line.id;
  }
  const config = {
    lines: lines.map((line) => ({ id: line.id, addresses: line.addresses })),
    appLines: sorted(Object.fromEntries(Object.entries(saved.pins).map(([p, line]) => [appKey(p), line]))),
    combine: saved.combine.on,
    shares: sorted(Object.fromEntries(lines.filter(open).map((line) => [line.id, saved.combine.weights[line.id] ?? 1]))),
    lanes: sorted(Object.fromEntries(lines.map((line) => [line.id, line.target]))),
    blocked: lines.filter((line) => line.blocked).map((line) => line.id),
    ipv6: true,
  };
  if (!config.combine) config.shares = {};
  return config;
}

async function apply(method = 'apply') {
  const config = policy();
  const hash = createHash('sha256').update(JSON.stringify(config)).digest('hex');
  const changed = hash !== saved.hash;
  if (!changed && method !== 'start') return;
  saved.revision += 1;
  saved.hash = hash;
  await persist();
  const applied = await command(method, { revision: { n: saved.revision, hash, config } });
  assert.equal(applied.n, saved.revision);
  // The test controller models Control's close-after-apply ordering. Only an
  // exhausted line which moved or is blocked closes its pre-revision flows.
  for (const line of saved.lines) {
    if (line.exhausted && (line.target !== line.id || line.blocked)) {
      await command('closeFlows', { opId: `cap-${saved.revision}-${line.id}`, selector: { line: line.id }, startedBefore: applied.point });
    }
  }
  return applied;
}

async function sample() {
  const [stats, totals] = await Promise.all([command('stats'), command('totals')]);
  latest = { stats: stats.engine, totals };
  return latest;
}
async function state() {
  if (fatalError) return { routing: { status: 'error', error: fatalError }, lines: saved.lines, apps: [], combine: saved.combine };
  if (!ready) return { routing: { status: saved.on ? 'starting' : 'off', ipv6: true }, lines: saved.lines, apps: [], combine: saved.combine };
  await sample();
  const apps = new Map();
  for (const [p, line] of Object.entries(saved.pins)) apps.set(appKey(p), { path: p, line, connections: {} });
  let cursor = '';
  do {
    const page = await command('flows', { cursor });
    for (const f of page.flows) {
      if (!f.app?.path || f.closing) continue;
      const key = f.app.id;
      const app = apps.get(key) ?? { path: f.app.path, line: saved.pins[f.app.path] ?? null, connections: {} };
      app.connections[f.line] = (app.connections[f.line] ?? 0) + 1;
      apps.set(key, app);
    }
    cursor = page.cursor ?? '';
  } while (cursor);
  return { routing: { status: 'on', ipv6: true }, lines: saved.lines, apps: [...apps.values()],
    combine: { ...saved.combine, active: saved.combine.on && Object.keys(policy().shares).length > 1 }, engine: latest.stats };
}
async function stopEngine() {
  stopping = true;
  ready = false;
  try {
    if (pipe && !pipe.destroyed) await command('stop');
    if (engine) {
      if (engine.exitCode === null && engine.signalCode === null) {
        await once(engine, 'exit', { signal: AbortSignal.timeout(20_000) });
      }
      assert.equal(engine.exitCode, 0, 'Engine cleanup failed');
    }
    pipe?.destroy();
  } finally { stopping = false; }
}

async function api(route, body) {
  switch (route) {
  case 'state': return state();
  case 'engine-command': return command(body.method, body.fields ?? {}, body.timeout);
  case 'engine-heap': {
    assert(ready && heapProfile && engine?.exitCode === null, 'Hosted heap capture was not enabled for this live engine');
    const requestNonce = randomUUID().replaceAll('-', '');
    const sequence = ++heapProfile.sequence;
    const result = await exec(exe, ['heap-capture', '--profile-dir', heapProfile.directory,
      '--nonce', heapProfile.nonce, '--instance', instance, '--pid', String(engine.pid),
      '--sequence', String(sequence), '--request-nonce', requestNonce, '--label', String(body?.label ?? '')],
    { windowsHide: true, timeout: 30_000, maxBuffer: 128 << 10 });
    const capture = JSON.parse(result.stdout);
    assert(capture.Nonce === heapProfile.nonce && capture.Instance === instance && capture.PID === engine.pid &&
      capture.Request.Sequence === sequence && capture.Request.RequestNonce === requestNonce &&
      capture.ForcedGCAfter > capture.ForcedGCBefore && capture.Instrumented,
    'Heap response did not prove a fresh capture from this engine');
    return capture;
  }
  case 'lines/add': {
    const a = adapters.find((a) => a.alias === body.alias);
    assert(a, `Missing adapter ${body.alias}`);
    saved.lines.push({ ...a, strict: false, cap: null });
    break;
  }
  case 'app-line':
    if (body.line === null) delete saved.pins[body.path]; else saved.pins[body.path] = body.line;
    break;
  case 'combine': saved.combine = { on: body.on, weights: body.weights }; break;
  case 'lines/order':
    assert.equal(new Set(body.ids).size, saved.lines.length);
    saved.lines = body.ids.map((id) => saved.lines.find((line) => line.id === id));
    assert(saved.lines.every(Boolean)); break;
  case 'lines/update': {
    const line = saved.lines.find((line) => line.id === body.id);
    assert(line);
    for (const key of ['strict', 'cap']) if (Object.hasOwn(body, key)) line[key] = body[key];
    await sample(); break;
  }
  case 'routing':
    saved.on = body.on; await persist();
    if (body.on) { if (!ready) await launch(); } else await stopEngine();
    return true;
  case 'quit':
    saved.on = false; await persist(); await stopEngine();
    setTimeout(() => process.exit(0), 50);
    return true;
  default: throw new Error(`Unsupported test-controller action: ${route}`);
  }
  await apply();
  return true;
}

async function health() {
  if (!ready || healthBusy || stopping) return;
  healthBusy = true;
  try {
    const { engine: stats } = await command('stats');
    for (const line of saved.lines) {
      if (!ready || stopping) return;
      const binding = stats.bindings?.[line.id];
      let up = Boolean(binding?.up && binding?.default4);
      if (up) {
        const probe = async (operator) => {
          const result = await command('probe', { opId: randomUUID(), line: line.id, operator });
          if (result.outcome === 'engineUnavailable') throw new Error(result.error);
          return result;
        };
        const quick = await probe('quick:cloudflare');
        if (line.up && quick.ok) continue;
        if (!line.up) up = (await probe('cloudflare')).ok;
        else {
          const first = await probe('google');
          up = first.ok || (await probe('quad9')).ok;
        }
      }
      if (line.up !== up) {
        await serially(async () => {
          line.up = up;
          console.log(`LINE HEALTH ${JSON.stringify({ id: line.id, up })}`);
          await apply();
        });
      }
    }
  } catch (error) {
    // An unavailable engine never becomes a line failure.
    console.error(`HEALTH ENGINE UNAVAILABLE ${error.message}`);
  } finally { healthBusy = false; }
}

try {
  adapters = JSON.parse((await exec(exe, ['interfaces'], { windowsHide: true })).stdout);
  try { saved = JSON.parse(await readFile(settingsFile, 'utf8')); }
  catch (error) {
    if (error.code !== 'ENOENT') throw error;
    const first = adapters.find((a) => a.up && a.default4);
    assert(first, 'No usable physical default for acceptance');
    saved = { lines: [{ ...first, strict: false, cap: null }], pins: {}, combine: { on: false, weights: {} }, revision: 0, hash: '', on: true };
  }
  // A new driver may attach before the old lease lapses. Do not run recovery
  // against that live engine. The original PID file remains authoritative.
  try {
    const pid = Number(await readFile(path.join(directory, 'engine.pid'), 'utf8'));
    process.kill(pid, 0);
    await connect();
    await apply('start');
    ready = true;
  } catch {
    pipe?.destroy();
    await launch();
  }
  process.send({ ready: true });
  setInterval(() => { if (ready) command('renew').catch((error) => console.error(error.message)); }, 5000).unref();
  setInterval(health, 1000).unref();
  process.on('message', ({ id, route, body }) => {
    serially(() => api(route, body)).then(
      (result) => process.send?.({ id, result }),
      (error) => process.send?.({ id, error: error.stack }),
    );
  });
  process.on('disconnect', () => process.exit(0));
} catch (error) {
  console.error(error);
  process.exit(1);
}
