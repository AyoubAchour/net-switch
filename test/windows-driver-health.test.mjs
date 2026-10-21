import assert from 'node:assert/strict';
import { createHash, randomUUID } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import test from 'node:test';
import vm from 'node:vm';

const driver = (await readFile(new URL('../tests/windows/engine-driver.mjs', import.meta.url), 'utf8')).replaceAll('\r\n', '\n');

// Run the actual controller functions without its native process/pipe bootstrap.
// Only I/O is substituted; health, the API queue, policy and apply are verbatim.
function section(start, end) {
  const first = driver.indexOf(start);
  const last = driver.indexOf(end, first + start.length);
  assert(first >= 0 && last > first, `Driver source boundary missing: ${start}`);
  return driver.slice(first, last);
}
const controllerSource = [
  section('let queue = Promise.resolve();', 'async function persist()'),
  section('function policy() {', 'async function state()'),
  section('async function api(route, body) {', '\ntry {\n  adapters ='),
].join('\n');

function deferred() {
  let resolve;
  const promise = new Promise((done) => { resolve = done; });
  return { promise, resolve };
}

function controller() {
  const adapters = [
    { id: 'main', alias: 'Ethernet', up: true, default4: true, addresses: ['192.0.2.1'] },
    { id: 'second', alias: 'TestISP', up: true, default4: true, addresses: ['198.18.0.1'] },
  ];
  const saved = { lines: [{ ...adapters[0], strict: false, cap: null }], pins: {},
    combine: { on: false, weights: {} }, revision: 0, hash: '', on: true };
  const evidence = { commands: [], applies: [], persisted: [], logs: [], errors: [] };
  let bindings = {};
  let probe = async () => ({ ok: true, outcome: 'ok' });
  const context = vm.createContext({
    assert, createHash, randomUUID, saved, adapters, latest: undefined,
    ready: true, stopping: false, healthBusy: false, instance: 'engine-1', epoch: 1,
    console: { log: (value) => evidence.logs.push(value), error: (value) => evidence.errors.push(value) },
    persist: async () => { evidence.persisted.push(structuredClone(saved)); },
    command: async (method, fields = {}) => {
      evidence.commands.push({ method, fields: structuredClone(fields) });
      switch (method) {
      case 'stats': return { engine: { bindings: structuredClone(bindings) } };
      case 'totals': return { lines: {} };
      case 'probe': return probe(fields);
      case 'apply': {
        evidence.applies.push(structuredClone(fields.revision));
        bindings = Object.fromEntries(fields.revision.config.lines.map(({ id }) =>
          [id, structuredClone(adapters.find((adapter) => adapter.id === id))]));
        return { n: fields.revision.n, hash: fields.revision.hash, point: fields.revision.n };
      }
      default: assert.fail(`Unexpected native command: ${method}`);
      }
    },
  });
  const functions = vm.runInContext(`${controllerSource}\n({
    health,
    api: (route, body) => serially(() => api(route, body)),
    apply: () => serially(() => apply()),
  })`, context, { filename: 'engine-driver-health-under-test.mjs' });
  return { ...functions, saved, evidence, setProbe: (fn) => { probe = fn; } };
}

test('health preserves a line added and pinned during an earlier line probe', { timeout: 5000 }, async (t) => {
  const c = controller();
  await c.apply();
  // Accumulate real health samples on one controller; never reset before the race.
  await c.health();
  await c.health();
  assert.equal(c.saved.revision, 1);
  assert.equal(c.evidence.applies.length, 1);
  const entered = deferred(), release = deferred();
  c.setProbe(async ({ line, operator }) => {
    if (line === 'main' && operator === 'quick:cloudflare') {
      entered.resolve();
      await release.promise;
    }
    return { ok: true, outcome: 'ok' };
  });
  const snapshotRevision = c.saved.revision;
  const sampling = c.health();
  await entered.promise;
  await c.api('lines/add', { alias: 'TestISP' });
  await c.api('app-line', { path: 'acceptance-app.exe', line: 'main' });
  await c.api('app-line', { path: 'acceptance-app.exe', line: 'second' });
  const second = c.saved.lines.find(({ id }) => id === 'second');
  assert.equal(second.up, true, 'The added line must start healthy');
  assert.equal(second.target, 'second', 'The committed pin must start on TestISP');
  assert.equal(c.saved.revision, 4);
  const commandsBeforeResume = c.evidence.commands.length;
  release.resolve();
  await sampling;
  const oldWouldPass = second.up && second.target === 'second' &&
    c.saved.pins['acceptance-app.exe'] === 'second';
  t.diagnostic(JSON.stringify({
    oldWouldPass, snapshotRevision, revision: c.saved.revision,
    pinned: c.saved.pins['acceptance-app.exe'], up: second.up, laneTarget: second.target,
    commandsAfterResume: c.evidence.commands.slice(commandsBeforeResume), logs: c.evidence.logs,
  }));
  assert.deepEqual(c.evidence.errors, []);
  // This is the original pin's required lane, not a changed acceptance oracle.
  // It proves controller ordering only; native interface traffic stays in acceptance.mjs.
  assert.equal(oldWouldPass, true, 'A pre-add health snapshot must not reroute the new pin');
  assert.equal(c.saved.revision, 4, 'Stale health must not create a fallback revision');
});
