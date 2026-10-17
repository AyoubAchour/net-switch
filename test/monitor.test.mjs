import assert from 'node:assert/strict';
import { spawn as spawnProcess } from 'node:child_process';
import { EventEmitter, once } from 'node:events';
import { existsSync } from 'node:fs';
import { networkInterfaces } from 'node:os';
import path from 'node:path';
import { createInterface } from 'node:readline';
import { PassThrough } from 'node:stream';
import { setTimeout as delay } from 'node:timers/promises';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { parseOutsideId } from '../lib/apps.mjs';
import { ADAPTER_STATS, findHelper, LineMonitor } from '../lib/monitor.mjs';
import { runFile, runPowerShellJson } from '../lib/ps.mjs';

const reading = (...adapters) => JSON.stringify({ adapters: adapters.map(([alias, rx, tx]) => ({ alias, rx, tx })) });

// The native helper, when this checkout has built it (npm run build:helper).
const ROOT = fileURLToPath(new URL('..', import.meta.url));
const HELPER = path.join(ROOT, 'helper', 'bin', 'netswitch-helper.exe');
const needsHelper = { skip: existsSync(HELPER) ? false : 'helper\\bin\\netswitch-helper.exe is not built; run npm run build:helper' };

test('the line meters read adapter counters through .NET, so the USB Wi-Fi stick is listed', async () => {
  // The same Windows PowerShell 5.1 the monitor runs in.
  const list = await runPowerShellJson(`${ADAPTER_STATS}\nConvertTo-Json -InputObject @($adapters) -Compress`);
  assert.ok(Array.isArray(list) && list.length > 0);
  for (const item of list) {
    assert.equal(typeof item.alias, 'string');
    assert.ok(Number.isFinite(item.rx) && item.rx >= 0, `${item.alias} rx`);
    assert.ok(Number.isFinite(item.tx) && item.tx >= 0, `${item.alias} tx`);
  }
  // Every adapter that has an internet-style address is there (the engine's own tunnel is not one of the lines).
  const withAddress = Object.entries(networkInterfaces())
    .filter(([name, entries]) => name !== 'NetSwitch' && entries.some((entry) => entry.family === 'IPv4' && !entry.internal))
    .map(([name]) => name);
  for (const name of withAddress) assert.ok(list.some((item) => item.alias === name), `${name} is missing from the counters`);
});

test('the real meters helper reports a speed for a connected adapter within a few seconds', { timeout: 20_000 }, async () => {
  // Adapter names differ between PCs ("Ethernet" here, something else on a CI
  // machine), so use whichever one has an internet-style address.
  const alias = Object.entries(networkInterfaces())
    .find(([name, entries]) => name !== 'NetSwitch' && entries.some((entry) => entry.family === 'IPv4' && !entry.internal))?.[0];
  assert.ok(alias, 'no connected adapter to measure');
  const monitor = new LineMonitor({ watchOutside: false, enginePath: '' });
  monitor.start();
  try {
    const until = Date.now() + 15_000;
    while (Date.now() < until && !monitor.rate(alias)) await delay(250);
    const rate = monitor.rate(alias);
    assert.ok(rate && Number.isFinite(rate.down) && Number.isFinite(rate.up), `no speed arrived for ${alias}`);
    assert.equal(monitor.isFresh(), true);
  } finally {
    monitor.stop();
  }
});

test('the native meters helper lists the same adapters as .NET does in PowerShell, in the same shape', needsHelper, async () => {
  const [output, list] = await Promise.all([
    runFile(HELPER, ['meters', '--once']),
    runPowerShellJson(`${ADAPTER_STATS}\nConvertTo-Json -InputObject @($adapters) -Compress`),
  ]);
  // One line, and only that.
  assert.equal(output.indexOf('\n'), output.length - 1);
  const sample = JSON.parse(output);
  assert.deepEqual(Object.keys(sample), ['adapters']);
  assert.ok(sample.adapters.length > 0);
  for (const item of sample.adapters) {
    assert.deepEqual(Object.keys(item), ['alias', 'rx', 'tx']);
    assert.equal(typeof item.alias, 'string');
    assert.ok(Number.isSafeInteger(item.rx) && item.rx >= 0, `${item.alias} rx`);
    assert.ok(Number.isSafeInteger(item.tx) && item.tx >= 0, `${item.alias} tx`);
  }
  const aliases = (items) => items.map((item) => item.alias).sort();
  assert.deepEqual(aliases(sample.adapters), aliases(list));
});

test('the native outside helper reports connections around routing in the PowerShell shape', needsHelper, async (t) => {
  const sample = JSON.parse(await runFile(HELPER, ['outside', '--once']));
  assert.deepEqual(Object.keys(sample), ['estats', 'outside']);
  assert.equal(typeof sample.estats, 'boolean');
  assert.ok(Array.isArray(sample.outside));
  for (const entry of sample.outside) {
    assert.deepEqual(Object.keys(entry), ['id', 'pid', 'path', 'local', 'created', 'down', 'up']);
    const id = parseOutsideId(entry.id);
    assert.ok(id, entry.id);
    assert.deepEqual([id.local, id.pid, id.created], [entry.local, entry.pid, entry.created]);
    assert.match(entry.created, /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{7}Z$/);
    assert.ok(Number.isFinite(Date.parse(entry.created)));
    assert.equal(typeof entry.path, 'string');
    assert.ok(!['127.0.0.1', '0.0.0.0', '198.18.0.1'].includes(entry.local), entry.id);
    // Without administrator rights Windows won't measure a connection: then both are null.
    assert.equal(entry.down === null, entry.up === null);
    for (const bytes of [entry.down, entry.up]) assert.ok(bytes === null || (Number.isSafeInteger(bytes) && bytes >= 0));
  }
  t.diagnostic(`${sample.outside.length} connections, ${sample.outside.filter((entry) => entry.down !== null).length} measured`);

  // The engine's own connections are left out, whatever the case of its path.
  const owner = sample.outside.find((entry) => entry.path)?.path;
  if (!owner) {
    t.diagnostic('no connection with a known program to leave out');
    return;
  }
  const without = JSON.parse(await runFile(HELPER, ['outside', '--once', '--engine', owner.toUpperCase()]));
  assert.ok(!without.outside.some((entry) => entry.path.toLowerCase() === owner.toLowerCase()), `${owner} was not left out`);
});

test('the native helper ends by itself when the server is gone, or when it closes its input', { ...needsHelper, timeout: 15_000 }, async (t) => {
  const started = [];
  t.after(() => started.forEach((child) => child.exitCode === null && child.kill()));
  const run = (args) => {
    const child = spawnProcess(HELPER, args, { windowsHide: true, stdio: ['pipe', 'pipe', 'pipe'] });
    started.push(child);
    const lines = [];
    createInterface({ input: child.stdout }).on('line', (line) => lines.push(line));
    return { child, lines };
  };

  // A stand-in server that lives for a moment.
  const server = spawnProcess(process.execPath, ['-e', 'setTimeout(() => {}, 2500)'], { stdio: 'ignore' });
  started.push(server);
  const meters = run(['meters', '--parent', String(server.pid)]);
  await once(server, 'exit');
  const serverGoneAt = Date.now();
  const [code] = await once(meters.child, 'exit');
  assert.equal(code, 0);
  assert.ok(Date.now() - serverGoneAt < 2000, 'it outlived the server');
  assert.ok(meters.lines.length >= 1 && meters.lines.every((line) => Array.isArray(JSON.parse(line).adapters)));

  const outside = run(['outside']);
  await once(outside.child.stdout, 'data');
  outside.child.stdin.end();
  const [closedCode] = await once(outside.child, 'exit');
  assert.equal(closedCode, 0);
});

test('the real native helper gives the meters a speed within a few seconds', { ...needsHelper, timeout: 20_000 }, async () => {
  const alias = Object.entries(networkInterfaces())
    .find(([name, entries]) => name !== 'NetSwitch' && entries.some((entry) => entry.family === 'IPv4' && !entry.internal))?.[0];
  assert.ok(alias, 'no connected adapter to measure');
  const monitor = new LineMonitor({ watchOutside: false, enginePath: '', helperPath: HELPER });
  monitor.start();
  try {
    const until = Date.now() + 15_000;
    while (Date.now() < until && !monitor.rate(alias)) await delay(250);
    const rate = monitor.rate(alias);
    assert.ok(rate && Number.isFinite(rate.down) && Number.isFinite(rate.up), `no speed arrived for ${alias}`);
    assert.equal(monitor.isFresh(), true);
  } finally {
    monitor.stop();
  }
});

test('the helper is found where the installer puts it, or where a source build puts it', () => {
  const root = path.join('C:', 'Program Files', 'Net Switch');
  const installed = path.join(root, 'helper', 'netswitch-helper.exe');
  const built = path.join(root, 'helper', 'bin', 'netswitch-helper.exe');
  assert.equal(findHelper(root, (file) => file === installed || file === built), installed);
  assert.equal(findHelper(root, (file) => file === built), built);
  assert.equal(findHelper(root, () => false), null);
});

test('speed is the growth between two readings, and a counter that restarts never gives a negative speed', () => {
  const monitor = new LineMonitor({ watchOutside: false, enginePath: '' });
  assert.equal(monitor.handleLine(reading(['Wi-Fi', 1000, 50])), true);
  assert.equal(monitor.rate('Wi-Fi'), null);
  monitor.adapters.get('Wi-Fi').at -= 1000;
  monitor.handleLine(reading(['Wi-Fi', 51_000, 150]));
  const rate = monitor.rate('Wi-Fi');
  assert.ok(Math.abs(rate.down - 50_000) < 2_000 && Math.abs(rate.up - 100) < 10, JSON.stringify(rate));
  // The adapter reconnects and its counters start again.
  monitor.adapters.get('Wi-Fi').at -= 1000;
  monitor.handleLine(reading(['Wi-Fi', 10, 5]));
  assert.deepEqual(monitor.rate('Wi-Fi'), { down: 0, up: 0 });
});

test('an adapter that goes away shows no speed, and one that comes back starts again', () => {
  const monitor = new LineMonitor({ watchOutside: false, enginePath: '' });
  monitor.handleLine(reading(['Ethernet', 1, 1], ['Wi-Fi', 1, 1]));
  monitor.adapters.get('Wi-Fi').at -= 1000;
  monitor.handleLine(reading(['Ethernet', 2, 2], ['Wi-Fi', 5001, 1]));
  assert.ok(monitor.rate('Wi-Fi'));
  monitor.handleLine(reading(['Ethernet', 3, 3]));
  assert.equal(monitor.rate('Wi-Fi'), null);
  monitor.handleLine(reading(['Ethernet', 4, 4], ['Wi-Fi', 9000, 1]));
  assert.equal(monitor.rate('Wi-Fi'), null);
});

test('a reading with an empty or broken entry, or no adapters at all, does not break the meters', () => {
  const monitor = new LineMonitor({ watchOutside: false, enginePath: '' });
  assert.equal(monitor.handleLine('{"adapters":[null,{"alias":"Wi-Fi","rx":1,"tx":1}]}'), true);
  assert.equal(monitor.handleLine('{"adapters":[]}'), true);
  assert.equal(monitor.handleLine('not json'), false);
  assert.equal(monitor.rate('Wi-Fi'), null);
});

test('only a reading with connections that go around routing is announced as a sample', () => {
  const monitor = new LineMonitor({ watchOutside: true, enginePath: 'sing-box.exe' });
  const samples = [];
  monitor.on('sample', (sample) => samples.push(sample));
  monitor.handleLine(reading(['Ethernet', 1, 1]));
  assert.equal(samples.length, 0);
  assert.equal(monitor.isFresh(), false);
  monitor.handleLine(JSON.stringify({ estats: true, outside: [{ id: 'a' }] }));
  assert.equal(samples.length, 1);
  assert.deepEqual(samples[0].outside, [{ id: 'a' }]);
  assert.equal(monitor.isFresh(), true);
});

test('without the second helper, as in test mode, the meters tell whether the monitor is alive', () => {
  const monitor = new LineMonitor({ watchOutside: false, enginePath: '' });
  assert.equal(monitor.isFresh(), false);
  monitor.handleLine(reading(['Ethernet', 1, 1]));
  assert.equal(monitor.isFresh(), true);
});

// A stand-in for a helper process.
function fakeSpawn() {
  const children = [];
  const spawn = () => {
    const child = Object.assign(new EventEmitter(), { stdout: new PassThrough(), stderr: new PassThrough(), killed: false });
    child.kill = () => {
      child.killed = true;
      child.emit('exit');
    };
    children.push(child);
    return child;
  };
  return { spawn, children };
}

test('a helper that goes silent is ended and started again, and a meter helper never blocks the other', async () => {
  const { spawn, children } = fakeSpawn();
  const monitor = new LineMonitor({ watchOutside: true, enginePath: '', spawn, silentMs: 60, watchdogMs: 20, restartMinMs: 30 });
  monitor.start();
  try {
    assert.equal(children.length, 2);
    // The meters keep talking; the outside helper does not.
    const talking = setInterval(() => children[0].stdout.write(`${reading(['Ethernet', 1, 1])}\n`), 20);
    await delay(250);
    clearInterval(talking);
    assert.equal(children[0].killed, false);
    assert.equal(children[1].killed, true);
    // It came back: a third helper was started in its place.
    assert.ok(children.length >= 3);
  } finally {
    monitor.stop();
  }
});

test('with the native helper, each mode runs from it, following this server and leaving out the engine', async () => {
  const { spawn, children } = fakeSpawn();
  const calls = [];
  const spawnHelper = (file, args) => {
    calls.push([file, args]);
    return spawn();
  };
  let powershell = 0;
  const helperPath = 'C:\\Program Files\\Net Switch\\helper\\netswitch-helper.exe';
  const enginePath = 'C:\\Program Files\\Net Switch\\engine\\sing-box.exe';
  const monitor = new LineMonitor({
    watchOutside: true,
    enginePath,
    helperPath,
    spawn: () => {
      powershell += 1;
      return spawn();
    },
    spawnHelper,
    restartMinMs: 30,
    watchdogMs: 20,
    silentMs: 100000,
  });
  monitor.start();
  try {
    const parent = String(process.pid);
    assert.deepEqual(calls, [
      [helperPath, ['meters', '--parent', parent]],
      [helperPath, ['outside', '--parent', parent, '--engine', enginePath]],
    ]);
    assert.equal(powershell, 0);
    // Its lines are read like the PowerShell ones.
    children[0].stdout.write(`${reading(['Ethernet', 1, 1])}\n`);
    children[1].stdout.write(`${JSON.stringify({ estats: true, outside: [] })}\n`);
    await delay(20);
    assert.ok(monitor.adapters.has('Ethernet'));
    assert.equal(monitor.isFresh(), true);
    // One that ends is started again the same way.
    children[1].emit('exit');
    await delay(80);
    assert.deepEqual(calls[2], calls[1]);
    assert.equal(powershell, 0);
  } finally {
    monitor.stop();
  }

  // Without routing to watch, only the meters run; without an engine path, none is passed.
  calls.length = 0;
  for (const watchOutside of [false, true]) {
    const other = new LineMonitor({ watchOutside, enginePath: '', helperPath, spawnHelper });
    other.start();
    other.stop();
  }
  assert.deepEqual(calls.map(([, args]) => args), [
    ['meters', '--parent', String(process.pid)],
    ['meters', '--parent', String(process.pid)],
    ['outside', '--parent', String(process.pid)],
  ]);
});

test('a helper that keeps dying is restarted after longer and longer waits', async () => {
  const { spawn, children } = fakeSpawn();
  const monitor = new LineMonitor({ watchOutside: false, enginePath: '', spawn, restartMinMs: 40 });
  monitor.start();
  try {
    children[0].emit('exit');
    await delay(25);
    assert.equal(children.length, 1);
    await delay(40);
    assert.equal(children.length, 2);
    children[1].emit('exit');
    await delay(60);
    // The second wait is twice as long.
    assert.equal(children.length, 2);
    await delay(60);
    assert.equal(children.length, 3);
  } finally {
    monitor.stop();
  }
});

test('a helper that could not start (an error and no exit) is started again', async () => {
  const { spawn, children } = fakeSpawn();
  const monitor = new LineMonitor({ watchOutside: false, enginePath: '', spawn, restartMinMs: 30, watchdogMs: 20, silentMs: 100000 });
  monitor.start();
  try {
    assert.equal(children.length, 1);
    children[0].emit('error', new Error('spawn powershell.exe ENOENT'));
    await delay(80);
    assert.equal(children.length, 2);
    // An error followed by an exit is still one restart.
    children[1].emit('error', new Error('boom'));
    children[1].emit('exit');
    children[1].emit('close');
    await delay(150);
    assert.equal(children.length, 3);
    // The wait before the next restart doubled once, not once per event.
    assert.equal(monitor.helpers.get('meters').restartDelay, 120);
  } finally {
    monitor.stop();
  }
});

test('an error from a helper that is running, such as a failed kill, does not replace it; its exit does', async () => {
  const { spawn, children } = fakeSpawn();
  const monitor = new LineMonitor({ watchOutside: false, enginePath: '', spawn, restartMinMs: 30, watchdogMs: 20, silentMs: 100000 });
  monitor.start();
  try {
    children[0].pid = 4321;
    children[0].emit('error', new Error('kill EPERM'));
    await delay(120);
    assert.equal(children.length, 1);
    children[0].emit('exit');
    await delay(80);
    assert.equal(children.length, 2);
  } finally {
    monitor.stop();
  }
});

test('the meter script gives an empty list, a one-item list and a full list, and skips an adapter whose counters fail', async () => {
  const real = '[System.Net.NetworkInformation.NetworkInterface]::GetAllNetworkInterfaces()';
  assert.ok(ADAPTER_STATS.includes(real));
  const fake = (names, failing = []) =>
    `@(${names
      .map(
        (name) =>
          `([pscustomobject]@{ Name = '${name}' } | Add-Member -MemberType ScriptMethod -Name GetIPStatistics -Value { ${
            failing.includes(name) ? "throw 'no counters'" : '[pscustomobject]@{ BytesReceived = 7; BytesSent = 8 }'
          } } -PassThru)`,
      )
      .join(', ')})`;
  const run = async (source) => {
    const script = `$ErrorActionPreference = 'SilentlyContinue'\n${ADAPTER_STATS.replace(real, source)}\n[pscustomobject]@{ adapters = @($adapters) } | ConvertTo-Json -Compress -Depth 4`;
    return runPowerShellJson(script);
  };
  assert.deepEqual((await run('@()')).adapters, []);
  assert.deepEqual((await run(fake(['only']))).adapters, [{ alias: 'only', rx: 7, tx: 8 }]);
  assert.deepEqual(
    (await run(fake(['good', 'broken', 'good2'], ['broken']))).adapters.map((item) => item.alias),
    ['good', 'good2'],
  );
});
