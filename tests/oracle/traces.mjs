import assert from 'node:assert/strict';
import { fileURLToPath } from 'node:url';
import { oracle } from './harness.mjs';
import { BASELINE, lines } from './record.mjs';
import provenance from './provenance.json' with { type: 'json' };

const interfaces = {
  Ethernet: [{ family: 'IPv4', address: '192.0.2.1', internal: false }],
  'Wi-Fi': [{ family: 'IPv4', address: '192.0.2.2', internal: false }],
};
const adapters = lines.map((line, index) => ({ ...line, connected: true, ipv4s: [`192.0.2.${index + 1}`], metric: 10 }));
const http = (route, body) => ({ kind: 'http', method: body === undefined ? 'GET' : 'POST', route: `/api/${route}`, ...(body === undefined ? {} : { body }) });
const tick = (ms) => ({ kind: 'tick', ms });
const meters = (rx) => ({ kind: 'helper-line', line: JSON.stringify({ adapters: [{ alias: 'Ethernet', rx, tx: 0 }, { alias: 'Wi-Fi', rx, tx: 0 }] }) });
const flow = (id, line) => ({ id, metadata: { processPath: 'C:\\Apps\\Firefox.exe' }, chains: [`line-${line}`], download: 10, upload: 2, start: '2026-10-19T12:00:00Z' });
const samples = { estats: true, outside: [{ id: '192.0.2.1:1234>203.0.113.1:443|42|2026-10-19T11:00:00Z', pid: 42, created: '2026-10-19T11:00:00Z', path: 'C:\\Apps\\Firefox.exe', local: '192.0.2.1', down: 10, up: 2 }] };
export const scenarios = {
  probeFailover: { steps: [tick(1000), { kind: 'probes', value: { a1: false } }, tick(30000), http('state'), { kind: 'probes', value: { a1: 25 } }, tick(11000), http('state')] },
  failoverFailback: { steps: [tick(1000), { kind: 'interfaces', value: { ...interfaces, Ethernet: [] } }, tick(2000), http('state'), { kind: 'interfaces', value: interfaces }, tick(2000), http('state')] },
  capMoved: { steps: [meters(0), tick(1000), http('lines/update', { id: 'b2', cap: { bytes: 100, period: 'day' } }), { kind: 'connections', value: [flow('phone-flow', 'b2')] }, meters(200), tick(2000), http('state')] },
  capBlockedAndMainException: { steps: [meters(0), tick(1000), http('lines/update', { id: 'a1', cap: { bytes: 100, period: 'day' } }), http('lines/update', { id: 'b2', cap: { bytes: 100, period: 'day' } }), { kind: 'connections', value: [flow('main-flow', 'a1'), flow('blocked-flow', 'b2')] }, meters(200), tick(2000), http('state')] },
  reconnectPinned: { initial: { appLines: { 'C:\\Apps\\Firefox.exe': 'b2' } }, steps: [{ kind: 'connections', value: [flow('off-line', 'a1'), flow('right-line', 'b2')] }, tick(1000), { kind: 'helper-line', line: JSON.stringify(samples) }, http('reconnect', { key: 'c:\\apps\\firefox.exe' })] },
  reconnectShared: { initial: { combine: true }, steps: [{ kind: 'connections', value: [flow('shared-main', 'a1'), flow('shared-second', 'b2')] }, tick(1000), { kind: 'helper-line', line: JSON.stringify(samples) }, http('reconnect', { key: 'c:\\apps\\firefox.exe' })] },
  combining: { steps: [http('combine', { on: true, mode: 'manual', weights: { a1: 1, b2: 3 } }), http('lines/update', { id: 'b2', strict: true }), http('state')] },
  ipv6: { steps: [{ kind: 'interfaces', value: Object.fromEntries(Object.entries(interfaces).map(([alias, entries]) => [alias, [...entries, { family: 'IPv6', address: '2001:db8::1', internal: false }]])) }, tick(31000), http('state'), { kind: 'interfaces', value: interfaces }, tick(31000), http('state')] },
  migration: { initial: { lines: [], mainAlias: 'Ethernet', secondAlias: 'Wi-Fi', secondApps: ['C:\\Apps\\Firefox.exe'], setupUndo: { metrics: { Ethernet: [{ family: 'IPv4', automatic: true, metric: 25 }] }, policy: 3 }, unknown: { keep: 1.25 } }, steps: [http('state'), http('quit', {})] },
};

scenarios.combiningNoOpenLine = { initial: { combine: true }, steps: scenarios.capBlockedAndMainException.steps };
scenarios.savedVersionOrder = { initial: { appLines: { 'C:\\Discord\\app-1.0.9\\Discord.exe': 'a1', 'C:\\Discord\\app-1.0.10\\Discord.exe': 'b2' } }, steps: [http('state')] };
scenarios.legacyCaseOrder = { initial: { lines: [], mainAlias: 'Ethernet', secondAlias: 'Wi-Fi', cableApps: ['c:\\apps\\x.exe'], secondApps: ['C:\\Apps\\X.exe'] }, steps: [http('state')] };
scenarios.midnightGap = { timezone: 'America/Santiago', now: Date.parse('2026-09-06T03:59:59Z'), initial: { lines: lines.map((line) => ({ ...line, cap: { bytes: 100, period: 'day' } })) }, steps: [meters(0), tick(1000), meters(200), tick(1000), http('state')] };
scenarios.busyFailedChecks = { steps: [tick(1000), { kind: 'probes', value: { a1: false } }, ...Array.from({ length: 35 }, (_, index) => [{ kind: 'connections', value: [{ ...flow('busy', 'a1'), download: (index + 1) * 1_000_000 }] }, tick(1000)]).flat(), http('state')] };

// Round-two scenarios extend the oracle. The original fourteen stay frozen.
scenarios.lineAdd = { initial: { lines: [lines[0]] }, steps: [http('lines/add', { alias: 'Wi-Fi' }), http('state')] };
scenarios.lineRemove = { steps: [http('lines/remove', { id: 'b2' }), http('state')] };
scenarios.lineOrder = { steps: [http('lines/order', { ids: ['b2', 'a1'] }), http('state')] };
scenarios.appLine = { steps: [http('app-line', { path: 'C:\\Apps\\Firefox.exe', line: 'b2' }), http('app-line', { path: 'C:\\Apps\\Firefox.exe', line: null }), http('state')] };
scenarios.routingAndReads = { steps: [http('ping'), http('installed-apps'), http('icon?key=missing'), http('routing', { on: false }), tick(2000), http('state'), http('routing', { on: true }), http('state')] };
scenarios.settingsSetupUpdate = { environment: { userDir: '/oracle/user', realUpdates: true }, steps: [
  http('settings', { autostart: true }), http('settings', { autostart: false }),
  http('settings', { checkForUpdates: false, probeTargets: ['1.0.0.1:443', '8.8.4.4:443'] }),
  http('setup/cable-default', {}), http('setup/keep-both', {}), http('setup/undo', {}),
  http('update/check', {}),
  { kind: 'release', value: { tag_name: 'v0.3.2', html_url: 'https://github.com/AyoubAchour/net-switch/releases/tag/v0.3.2', assets: [{ name: 'NetSwitch-Setup-0.3.2-x64.exe', browser_download_url: 'https://github.com/AyoubAchour/net-switch/releases/download/v0.3.2/NetSwitch-Setup-0.3.2-x64.exe' }] } },
  http('settings', { checkForUpdates: true }), http('update/dismiss', { version: '0.3.2' }), http('update/check', {}),
  { kind: 'updateStatus', value: 503 }, http('update/check', {}), http('state'),
] };
scenarios.capReset = { now: Date.parse('2026-10-19T23:59:57Z'), initial: { lines: lines.map((line) => ({ ...line, cap: { bytes: 100, period: 'day' } })) }, steps: [meters(0), tick(1000), meters(200), tick(1000), http('state'), tick(2000), http('state')] };
scenarios.hungEngine = { steps: [{ kind: 'connectionsStatus', value: 503 }, tick(20000), http('state'), { kind: 'connectionsStatus', value: 200 }, tick(1000), http('state')] };
scenarios.lostDefaultRoute = { steps: [tick(1000), { kind: 'routes', value: [{ interfaceAddress: '192.0.2.2' }] }, tick(4000), http('state'), tick(5000), http('state'), tick(1000), http('state'), { kind: 'routes', value: [{ interfaceAddress: '192.0.2.1' }, { interfaceAddress: '192.0.2.2' }] }, tick(5000), http('state')] };
scenarios.quitFailure = { steps: [{ kind: 'quitFailure', value: 'Access is denied' }, http('quit', {}), { kind: 'quitFailure', value: null }, http('quit', {})] };
const identified = lines.map((line, i) => ({ ...line, guid: `adapter-${i}` }));
scenarios.adapterRename = { initial: { lines: identified }, environment: { adapters: identified.map((line, i) => ({ ...adapters[i], ...line })) }, steps: [
  { kind: 'adapters', value: identified.map((line, i) => ({ ...adapters[i], ...line, alias: i === 0 ? 'LAN' : line.alias })) },
  { kind: 'interfaces', value: { LAN: interfaces.Ethernet, 'Wi-Fi': interfaces['Wi-Fi'] } },
  { kind: 'refresh-adapters' }, tick(1000), http('state'),
] };
for (const name of ['lineAdd', 'lineRemove', 'lineOrder', 'appLine', 'routingAndReads', 'settingsSetupUpdate', 'capReset', 'hungEngine', 'lostDefaultRoute', 'quitFailure', 'adapterRename']) {
  scenarios[name].environment = { ...scenarios[name].environment, realDirectoryList: true };
}

export async function recordTrace(name, scenario = scenarios[name]) {
  const previousTZ = process.env.TZ;
  process.env.TZ = scenario.timezone ?? 'UTC';
  const entries = [];
  const trace = (direction, kind, value) => entries.push({ seq: entries.length, direction, kind, value });
  const initial = { lines, ...scenario.initial };
  trace('input', 'initial-files', { settings: initial });
  const run = await oracle({ initial, trace, environment: { interfaces, adapters, ...scenario.environment, ...(scenario.now === undefined ? {} : { now: scenario.now }) } });
  for (const step of scenario.steps) {
    if (step.kind === 'http') await run.request(step.method, step.route, step.body);
    else if (step.kind === 'refresh-adapters') { trace('input', 'refresh-adapters', {}); await run.server.oracleHooks.refreshAdapters(); }
    else if (step.kind === 'tick') await run.advance(step.ms);
    else if (step.kind === 'helper-line') {
      trace('input', 'helper-line', { line: step.line });
      run.server.oracleHooks.monitor.handleLine(step.line);
    } else {
      trace('input', step.kind, step.value);
      run.environment[step.kind] = structuredClone(step.value);
    }
    await run.settle();
  }
  const states = entries.filter((entry) => entry.kind === 'api').map((entry) => entry.value.body.state ?? entry.value.body);
  const last = states.at(-1);
  const deleted = entries.filter((entry) => entry.direction === 'output' && entry.kind === 'engine' && entry.value.method === 'DELETE').map((entry) => entry.value.route);
  if (name === 'failoverFailback' || name === 'probeFailover') {
    assert.equal(states.at(-2).lines[0].target, 'b2');
    assert.equal(last.lines[0].target, 'a1');
    assert.deepEqual(deleted, []);
  }
  if (name === 'capMoved') assert.ok(deleted.includes('/connections/phone-flow'));
  if (name === 'capBlockedAndMainException' || name === 'combiningNoOpenLine') {
    assert.equal(last.lines[0].blocked, false);
    assert.equal(last.lines[1].blocked, true);
    assert.deepEqual(deleted, ['/connections/blocked-flow']);
  }
  if (name === 'combiningNoOpenLine') {
    assert.equal(last.combine.active, false);
    assert.deepEqual(Object.keys(run.server.oracleHooks.engine.shares), []);
    assert.equal(run.server.oracleHooks.engine.routesTo({ metadata: { sourcePort: 65535 } }), 'a1');
  }
  if (name === 'reconnectPinned') assert.deepEqual(deleted, ['/connections/off-line']);
  if (name === 'reconnectShared') assert.deepEqual(deleted, []);
  if (name.startsWith('reconnect')) assert.ok(entries.some((entry) => entry.kind === 'outside-close' && entry.value.items.length === 1));
  if (name === 'ipv6') {
    assert.equal(states.at(-2).routing.ipv6, true);
    assert.equal(last.routing.ipv6, false);
  }
  if (name === 'midnightGap') assert.equal(last.lines[0].usage.periodStart, Date.parse('2026-09-06T04:00:00Z'));
  if (name === 'busyFailedChecks') {
    assert.ok(entries.filter((entry) => entry.kind === 'probe-result' && entry.value.status === 503).length >= 3);
    assert.equal(last.lines[0].target, 'a1');
    assert.equal(last.lines[0].problem, null);
  }
  if (name === 'savedVersionOrder') assert.equal(last.apps.find((app) => /discord/i.test(app.path)).line, 'b2');
  if (name === 'legacyCaseOrder') assert.equal(last.apps.find((app) => /x.exe/i.test(app.path)).line, last.lines[1].id);
  const logs = entries.filter((entry) => entry.kind === 'log').map((entry) => entry.value.text);
  if (name === 'lineAdd') { assert.equal(last.lines.length, 2); assert.ok(logs.includes('added Wi-Fi (Wi-Fi)')); }
  if (name === 'lineRemove') { assert.equal(last.lines.length, 1); assert.ok(logs.includes('removed Wi-Fi (Wi-Fi)')); }
  if (name === 'lineOrder') { assert.equal(last.lines[0].id, 'b2'); assert.ok(logs.includes('line order: Wi-Fi, Ethernet')); }
  if (name === 'appLine') { assert.equal(states[0].apps[0].line, 'b2'); assert.equal(last.apps.length, 0); }
  if (name === 'routingAndReads') { assert.equal(states.at(-3).routing.status, 'off'); assert.equal(last.routing.status, 'on'); }
  if (name === 'settingsSetupUpdate') {
    assert.ok(logs.includes('starting with Windows is on')); assert.ok(logs.includes('starting with Windows is off'));
    assert.ok(logs.includes('Net Switch 0.3.2 is available (this is 0.3.1)'));
    assert.ok(logs.includes('could not check for updates: GitHub answered 503'));
    assert.deepEqual(last.setup.changed, { cableDefault: false, keepBoth: false });
  }
  if (name === 'capReset') { assert.ok(states[0].lines.every((line) => line.exhausted)); assert.ok(last.lines.every((line) => !line.exhausted)); assert.ok(logs.includes("Wi-Fi's data cap reset")); }
  if (name === 'hungEngine') { assert.ok(logs.includes("the routing engine hasn't answered for 20 polls; restarting it")); assert.equal(entries.filter((entry) => entry.kind === 'spawn').length, 2); }
  if (name === 'lostDefaultRoute') { assert.equal(states[0].lines[0].connected, true); assert.equal(states[1].lines[0].connected, true); assert.equal(states[2].lines[0].problem, 'no default route'); assert.equal(last.lines[0].connected, true); }
  if (name === 'quitFailure') assert.ok(logs.includes('quit failed: Access is denied'));
  if (name === 'adapterRename') { assert.equal(last.lines[0].alias, 'LAN'); assert.ok(logs.includes('routing restarts to use LAN, Wi-Fi')); }
  if (previousTZ === undefined) delete process.env.TZ;
  else process.env.TZ = previousTZ;
  const source = provenance.fixtures[name];
  return { version: 1, baseline: source?.baseline ?? BASELINE, hooks: source?.hooks ?? [], name, scenario, entries };
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const all = {};
  for (const name of process.argv[2] ? [process.argv[2]] : Object.keys(scenarios)) all[name] = await recordTrace(name);
  console.log(JSON.stringify(all));
}
