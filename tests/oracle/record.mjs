import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { STATES } from '../../test/tray-states.mjs';
import { oracle } from './harness.mjs';

export const BASELINE = '0172a6bf345e739ce1854d732934bd5ee9c713db';
const hash = (value) => createHash('sha256').update(JSON.stringify(value)).digest('hex');
const line = (id, alias, kind = 'wired') => ({ id, alias, guid: null, label: alias, kind, metered: false, strict: false, cap: null, weight: 1 });
export const lines = [line('a1', 'Ethernet'), line('b2', 'Wi-Fi', 'wifi')];

export async function record() {
  const fixture = { baseline: BASELINE, states: {}, routes: [], effects: [] };
  for (const [name, scenario] of Object.entries(STATES)) {
    const run = await oracle();
    for (const item of scenario.lines) run.environment.rates[item.alias] = item.rate;
    run.server.oracleHooks.seed(JSON.stringify(scenario));
    fixture.states[name] = await run.request('GET', '/api/state');
  }
  const run = await oracle({ initial: { lines } });
  const { environment: env, server: { oracleHooks: hooks } } = run;
  env.adapters = [...lines, line('c3', 'Phone', 'phone')].map((item, index) => ({ ...item, connected: true, ipv4s: [`192.0.2.${index + 1}`], metric: 10 - index }));
  env.interfaces = Object.fromEntries(env.adapters.map((item) => [item.alias, [{ family: 'IPv4', address: item.ipv4s[0], internal: false }]]));
  await hooks.refreshAdapters();
  for (let poll = 0; poll < 2; poll++) {
    env.now += 1000;
    await hooks.pollConnections();
    await run.settle();
  }
  const call = async (method, route, body, headers) => {
    const response = await run.request(method, route, body, headers);
    fixture.routes.push({ method, route, ...(body !== undefined ? { input: body } : {}), ...(headers ? { headers } : {}), response });
  };
  await call('GET', '/api/ping');
  await call('GET', '/api/state');
  await call('GET', '/api/installed-apps');
  await call('GET', '/api/icon?key=missing');
  await call('GET', '/api/ping', undefined, { 'x-token': '' });
  await call('GET', '/api/ping', undefined, { host: 'attacker.invalid' });
  await call('POST', '/api/routing', { on: false }, { origin: 'https://attacker.invalid' });
  await call('GET', '/api/missing');
  await call('POST', '/api/settings', '{');
  await call('POST', '/api/settings', ' '.repeat(65537));
  await call('POST', '/api/settings', { checkForUpdates: false, probeTargets: ['9.9.9.9:443'] });
  await call('POST', '/api/settings', { autostart: true });
  await call('POST', '/api/update/check', {});
  await call('POST', '/api/update/dismiss', { version: '0.3.2' });
  await call('POST', '/api/app-line', { path: 'C:\\Apps\\Firefox.exe', line: 'b2' });
  await call('POST', '/api/app-line', { path: '', line: 'b2' });
  await call('POST', '/api/lines/update', { id: 'b2', label: 'Phone data', metered: true, cap: { bytes: 1024, period: 'day' } });
  await call('POST', '/api/lines/update', { id: 'a1', strict: true });
  await call('POST', '/api/combine', { on: true, mode: 'manual', weights: { a1: 2, b2: 3 } });
  await call('POST', '/api/combine', { mode: 'invalid' });
  await call('POST', '/api/reconnect', { key: 'unknown' });
  env.connections = [{ id: 'old-flow', metadata: { processPath: 'C:\\Apps\\Firefox.exe' }, chains: ['line-a1'], download: 10, upload: 3, start: '2026-10-19T12:00:00Z' }];
  await hooks.pollConnections(); await run.settle();
  await call('POST', '/api/reconnect', { key: 'c:\\apps\\firefox.exe' });
  await call('POST', '/api/setup/cable-default', {});
  await call('POST', '/api/setup/keep-both', {});
  await call('POST', '/api/setup/undo', {});
  await call('POST', '/api/lines/add', { alias: 'Phone' });
  await call('POST', '/api/lines/remove', { id: hooks.settings.values.lines.at(-1).id });
  await call('POST', '/api/lines/order', { ids: ['b2', 'a1'] });
  await call('POST', '/api/routing', { on: false });
  await call('POST', '/api/routing', { on: true });
  await call('POST', '/api/quit', {});
  fixture.effects = run.outputs;
  // Huge malformed bodies are represented by their length and digest.
  for (const entry of fixture.routes) if (typeof entry.input === 'string' && entry.input.length > 1000) entry.input = { bytes: entry.input.length, sha256: hash(entry.input) };
  return fixture;
}

if (process.argv[1] === fileURLToPath(import.meta.url)) console.log(JSON.stringify(await record()));
