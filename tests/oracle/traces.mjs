import assert from 'node:assert/strict';
import { fileURLToPath } from 'node:url';
import { oracle } from './harness.mjs';
import { BASELINE, lines } from './record.mjs';

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

export async function recordTrace(name, scenario = scenarios[name]) {
  const entries = [];
  const trace = (direction, kind, value) => entries.push({ seq: entries.length, direction, kind, value });
  const initial = { lines, ...scenario.initial };
  trace('input', 'initial-files', { settings: initial });
  const run = await oracle({ initial, trace, environment: { interfaces, adapters } });
  for (const step of scenario.steps) {
    if (step.kind === 'http') await run.request(step.method, step.route, step.body);
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
  if (name === 'capBlockedAndMainException') {
    assert.equal(last.lines[0].blocked, false);
    assert.equal(last.lines[1].blocked, true);
    assert.deepEqual(deleted, ['/connections/blocked-flow']);
  }
  if (name === 'reconnectPinned') assert.deepEqual(deleted, ['/connections/off-line']);
  if (name === 'reconnectShared') assert.deepEqual(deleted, []);
  if (name.startsWith('reconnect')) assert.ok(entries.some((entry) => entry.kind === 'outside-close' && entry.value.items.length === 1));
  if (name === 'ipv6') {
    assert.equal(states.at(-2).routing.ipv6, true);
    assert.equal(last.routing.ipv6, false);
  }
  return { version: 1, baseline: BASELINE, name, scenario, entries };
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const all = {};
  for (const name of Object.keys(scenarios)) all[name] = await recordTrace(name);
  console.log(JSON.stringify(all));
}
