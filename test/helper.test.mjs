import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import { existsSync } from 'node:fs';
import { PassThrough } from 'node:stream';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { NetworkMonitor, NetworkUpdates, parseNetworkSnapshot, quickProbe, readPolicyOnce } from '../lib/helper.mjs';
import { LaneSwitch } from '../lib/lane-switch.mjs';
import { MissingAdapter, usableAddresses } from '../lib/network.mjs';
import { ADAPTERS_SCRIPT, readDefaultRoutes, readMinimizeConnectionsPolicy } from '../lib/platform/windows-network.mjs';
import { runFile, runPowerShellJson } from '../lib/ps.mjs';

const helper = fileURLToPath(new URL('../helper/bin/netswitch-helper.exe', import.meta.url));
const needsHelper = { skip: process.platform !== 'win32' || (existsSync(helper) ? false : 'native helper is not built'), timeout: 45_000 };
const sample = { readAt: 1000, adapters: [{ alias: 'Cable', index: 3, status: 'Up', ipv4s: ['192.168.1.2'] }], defaultRoutes: [], policy: 'absent' };

test('native adapters match the PowerShell scan field by field', needsHelper, async (t) => {
  const native = JSON.parse(await runFile(helper, ['network', '--once']));
  const shell = process.env.NETSWITCH_SCAN_TIMING === '1'
    ? await (await import('./powershell-scan-timing.mjs')).timedScan()
    : await runPowerShellJson(ADAPTERS_SCRIPT, { timeoutMs: 30_000 });
  assert.deepEqual(native.adapters.map((a) => a.alias).sort(), shell.map((a) => a.alias).sort(),
    `Visible adapter list differs. Native: ${JSON.stringify(native.adapters)}; PowerShell: ${JSON.stringify(shell)}`);
  for (const adapter of shell) {
    const actual = native.adapters.find((a) => a.index === adapter.index);
    assert.ok(actual, adapter.alias);
    assert.deepEqual(Object.keys(actual).sort(), Object.keys(adapter).sort());
    for (const [field, expected] of Object.entries(adapter)) {
      // Link negotiation can change between the two reads. Windows providers
      // also order multiple addresses differently; the chosen ipv4 must be a
      // member of the same set, not necessarily the same first item.
      if (field === 'linkSpeed' && /802\.11|Wireless LAN/i.test(adapter.mediaType)) {
        assert.match(actual[field], /^\d+(\.\d+)? [KMGT]?bps$/);
        if (actual[field] !== expected) t.diagnostic(`${adapter.alias}: speed changed ${actual[field]} -> ${expected}`);
      } else if (field === 'ipv4s') {
        assert.deepEqual([...actual[field]].sort(), [...expected].sort(), `${adapter.alias}.${field}`);
      } else if (field === 'ipv4' && adapter.ipv4s.length > 1) {
        assert.ok(adapter.ipv4s.includes(actual[field]));
      } else {
        assert.deepEqual(actual[field], expected, `${adapter.alias}.${field}`);
      }
    }
  }
  const sortRoutes = (routes) => routes.toSorted((a, b) => JSON.stringify(a).localeCompare(JSON.stringify(b)));
  assert.deepEqual(sortRoutes(native.defaultRoutes), sortRoutes(await readDefaultRoutes()));
  assert.equal(native.policy === 'absent' ? null : native.policy, await readMinimizeConnectionsPolicy());
  t.diagnostic(`${native.adapters.length} adapters, ${native.defaultRoutes.length} default routes; all stable fields matched`);
});

test('quickProbe preserves success/failure and rejects broken output and invalid options', async () => {
  const run = async (file, args, options) => {
    assert.equal(file, helper);
    assert.deepEqual(args, ['probe', '--interface-index', '19', '--targets', '1.1.1.1:443,8.8.8.8:443', '--timeout-ms', '2000']);
    assert.equal(options.timeoutMs, 5000);
    return '{"ok":true,"ms":23,"target":"1.1.1.1:443"}\n';
  };
  assert.deepEqual(await quickProbe(helper, 19, { run }), { ok: true, ms: 23, target: '1.1.1.1:443' });
  assert.deepEqual(await quickProbe(helper, 3, { run: async () => '{"ok":false,"error":"timed out"}' }), { ok: false, error: 'timed out' });
  for (const output of ['oops', '{}', '{"ok":true,"ms":-1,"target":"x"}', '{"ok":false}', '{"ok":true}\n{}']) {
    await assert.rejects(quickProbe(helper, 3, { run: async () => output }));
  }
  await assert.rejects(quickProbe(helper, 0));
  await assert.rejects(quickProbe(helper, 3, { timeoutMs: -1 }));
  await assert.rejects(quickProbe(helper, 3, { run: async () => { throw new Error('spawn failed'); } }), /spawn failed/);
});

function fakeChild() {
  const child = new EventEmitter();
  Object.assign(child, { pid: 123, stdout: new PassThrough(), stderr: new PassThrough(), kills: 0 });
  child.kill = () => { child.kills++; child.emit('exit', 1); };
  return child;
}

test('network snapshots reject partial reads and keep freshness separate from invalid output', () => {
  const monitor = new NetworkMonitor({ helperPath: helper });
  assert.throws(() => monitor.snapshot(), /no current snapshot/);
  for (const data of [{}, { ...sample, adapters: [] }, { ...sample, policy: null }, { ...sample, defaultRoutes: [{}] }]) {
    assert.throws(() => parseNetworkSnapshot(JSON.stringify(data)));
    assert.equal(monitor.handleLine(JSON.stringify(data)), false);
  }
  assert.equal(monitor.handleLine(JSON.stringify(sample)), true);
  assert.deepEqual(monitor.snapshot(), sample);
  assert.equal(monitor.handleLine(JSON.stringify({ ...sample, policy: 'unknown' })), true);
  monitor.emit('helperExit', 'network');
  assert.throws(() => monitor.snapshot(), /no current snapshot/);
  monitor.stop();
});

test('network stream restarts on death and silence, and stops its own helpers', async (t) => {
  t.mock.timers.enable({ apis: ['Date', 'setTimeout', 'setInterval'], now: 1000 });
  const children = [];
  const messages = [];
  const monitor = new NetworkMonitor({ helperPath: helper, silentMs: 70, watchdogMs: 10, restartMinMs: 15,
    log: (line) => messages.push(line), spawnHelper: (file, args) => {
      assert.equal(file, helper);
      assert.deepEqual(args, ['network', '--parent', String(process.pid)]);
      const child = fakeChild(); children.push(child); return child;
    },
  });
  try {
    monitor.start();
    monitor.start();
    assert.equal(children.length, 1);
    const ready = monitor.ready();
    children[0].stdout.write(JSON.stringify(sample) + '\n');
    assert.deepEqual(await ready, sample);
    children[0].emit('exit', 1);
    children[0].emit('close', 1);
    t.mock.timers.tick(15);
    assert.equal(children.length, 2);
    // Invalid lines must not keep a broken helper alive.
    for (let tick = 0; tick < 10; tick++) {
      children[1].stdout.write('{}\n');
      t.mock.timers.tick(10);
    }
    assert.equal(children[1].kills, 1);
    assert.ok(messages.some((line) => line.includes('stopped reporting')));
  } finally { monitor.stop(); }
  const count = children.length;
  t.mock.timers.tick(100);
  assert.equal(children.length, count);
});

test('lane health keeps checking Node addresses and route.exe when the helper dies or stalls', async (t) => {
  t.mock.timers.enable({ apis: ['Date'], now: 1000 });
  let fallback = [];
  let fallbackCalls = 0;
  const monitor = new NetworkMonitor({ helperPath: helper, readDefaultRoutes: async () => { fallbackCalls++; return fallback; } });
  const route = { gateway: '192.168.1.1', interfaceAddress: '192.168.1.2', metric: 25 };
  const update = (defaultRoutes) => monitor.handleLine(JSON.stringify({ ...sample, defaultRoutes }));
  let now = 0;
  let interfaces = { Cable: [{ family: 'IPv4', internal: false, address: '192.168.1.2' }] };
  const lane = new LaneSwitch({ engine: { status: 'off' }, lineId: 'a1', getLines: () => [{ id: 'a1', alias: 'Cable', label: 'Cable' }],
    now: () => now, usableAddresses: (alias) => usableAddresses(alias, () => interfaces), readDefaultRoutes: () => monitor.readDefaultRoutes(),
  });
  const sampleLane = async () => { lane.sample(); await lane.routeReading; now += 5000; };
  update([route]);
  await sampleLane();
  assert.equal(lane.isUp(), true);
  update([]);
  await sampleLane();
  assert.equal(lane.health.up, true, 'one missing route is not an outage');
  await sampleLane();
  await sampleLane();
  assert.equal(lane.health.up, false, 'two missing readings confirm the outage');
  update([route]);
  await sampleLane();
  await sampleLane();
  await sampleLane();
  assert.equal(lane.health.up, true);
  monitor.emit('helperExit', 'network');
  await sampleLane();
  await sampleLane();
  await sampleLane();
  assert.equal(lane.health.up, false, 'route.exe confirms the lost route after helper death');
  assert.ok(fallbackCalls > 0);
  fallback = [route];
  await sampleLane();
  await sampleLane();
  await sampleLane();
  assert.equal(lane.health.up, true, 'recovery is visible without a helper');
  update([route]);
  t.mock.timers.tick(15_001);
  fallback = [];
  assert.deepEqual(await monitor.readDefaultRoutes(), [], 'a silent helper falls back too');
  interfaces = {};
  await sampleLane();
  await sampleLane();
  await sampleLane();
  assert.equal(lane.health.up, false, 'Node notices unplugging despite the cached address');
});

test('policy-only reads accept known values and fail closed for Undo', async () => {
  for (const policy of ['absent', 0, 3]) {
    assert.equal(await readPolicyOnce(helper, async (file, args) => {
      assert.equal(file, helper);
      assert.deepEqual(args, ['policy']);
      return JSON.stringify({ policy });
    }), policy === 'absent' ? null : policy);
  }
  await assert.rejects(readPolicyOnce(helper, async () => '{"policy":"unknown"}'), /known Wi-Fi policy/);
  await assert.rejects(readPolicyOnce(helper, async () => { throw new Error('access denied'); }), /access denied/);
});

test('adapter replacement needs two readings and twenty seconds, and resets on recovery or selection', () => {
  const missing = new MissingAdapter();
  assert.equal(missing.update('cable', true, 0), false);
  assert.equal(missing.update('cable', true, 600), false);
  assert.equal(missing.update('cable', true, 19_999), false);
  assert.equal(missing.update('cable', true, 20_000), true);
  assert.equal(missing.update('cable', false, 20_001), false);
  assert.equal(missing.update('cable', true, 50_000), false);
  assert.equal(missing.update('new-cable', true, 80_000), false);
});

test('one-off and stream updates serialize and discard old or repeated readings', async () => {
  const applied = [];
  let release;
  const read = new Promise((resolve) => { release = resolve; });
  const queue = new NetworkUpdates(async (snapshot) => { applied.push(snapshot.readAt); }, () => read);
  const oneOff = queue.refresh();
  const olderStream = queue.refresh({ readAt: 10 });
  release({ readAt: 20 });
  await Promise.all([oneOff, olderStream]);
  await queue.refresh({ readAt: 20 });
  await queue.refresh({ readAt: 30 });
  assert.deepEqual(applied, [20, 30]);
});

test('native probe reports an unavailable interface without external traffic', needsHelper, async () => {
  const result = await quickProbe(helper, 0xffffffff, { targets: ['127.0.0.1:443'] });
  assert.equal(result.ok, false);
  assert.ok(result.error);
});
