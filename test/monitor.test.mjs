import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import { networkInterfaces } from 'node:os';
import { PassThrough } from 'node:stream';
import { setTimeout as delay } from 'node:timers/promises';
import { test } from 'node:test';
import { ADAPTER_STATS, LineMonitor } from '../lib/monitor.mjs';
import { runPowerShellJson } from '../lib/ps.mjs';

const reading = (...adapters) => JSON.stringify({ adapters: adapters.map(([alias, rx, tx]) => ({ alias, rx, tx })) });

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

test('the real meters helper reports a speed for the cable within a few seconds', { timeout: 20_000 }, async () => {
  const monitor = new LineMonitor({ watchOutside: false, enginePath: '' });
  monitor.start();
  try {
    const until = Date.now() + 15_000;
    while (Date.now() < until && !monitor.rate('Ethernet')) await delay(250);
    const rate = monitor.rate('Ethernet');
    assert.ok(rate && Number.isFinite(rate.down) && Number.isFinite(rate.up), 'no speed arrived');
    assert.equal(monitor.isFresh(), true);
  } finally {
    monitor.stop();
  }
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

// A stand-in for a PowerShell helper.
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
