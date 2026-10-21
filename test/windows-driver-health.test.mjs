import assert from 'node:assert/strict';
import { createHash, randomUUID } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import test from 'node:test';
import { setImmediate as nextTurn } from 'node:timers/promises';
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
  const physical = new Map(adapters.map((adapter) => [adapter.id, structuredClone(adapter)]));
  let bindings = {};
  let probe = async () => ({ ok: true, outcome: 'ok' });
  let stats = async (snapshot) => snapshot;
  let beforeApply = async () => {};
  const context = vm.createContext({
    assert, createHash, randomUUID, saved, adapters, latest: undefined,
    ready: true, stopping: false, healthBusy: false, instance: 'engine-1', epoch: 1,
    console: { log: (value) => evidence.logs.push(value), error: (value) => evidence.errors.push(value) },
    persist: async () => { evidence.persisted.push(structuredClone(saved)); },
    command: async (method, fields = {}) => {
      evidence.commands.push({ method, fields: structuredClone(fields) });
      switch (method) {
      case 'stats': return stats({ engine: { bindings: structuredClone(bindings) } });
      case 'totals': return { lines: {} };
      case 'probe': return probe(fields);
      case 'start':
      case 'apply': {
        await beforeApply(fields.revision);
        evidence.applies.push(structuredClone(fields.revision));
        bindings = Object.fromEntries(fields.revision.config.lines.filter(({ id }) => physical.has(id))
          .map(({ id }) => [id, structuredClone(physical.get(id))]));
        return { n: fields.revision.n, hash: fields.revision.hash, point: fields.revision.n };
      }
      default: assert.fail(`Unexpected native command: ${method}`);
      }
    },
  });
  const functions = vm.runInContext(`${controllerSource}\n({
    health,
    api: (route, body) => serially(() => api(route, body)),
    apply: (method) => serially(() => apply(method)),
    enqueue: (fn) => serially(fn),
  })`, context, { filename: 'engine-driver-health-under-test.mjs' });
  return { ...functions, saved, evidence,
    setProbe: (fn) => { probe = fn; },
    setStats: (fn) => { stats = fn; },
    setBeforeApply: (fn) => { beforeApply = fn; },
    setSession: (fields) => Object.assign(context, fields),
    setBinding: (id, fields) => {
      if (fields === null) { physical.delete(id); delete bindings[id]; }
      else {
        const value = { ...adapters.find((adapter) => adapter.id === id), ...fields };
        physical.set(id, value);
        bindings[id] = structuredClone(value);
      }
    },
  };
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
  const fresh = c.evidence.commands.length;
  await c.health();
  assert.deepEqual(probes(c, fresh, 'second'), ['quick:cloudflare'], 'The next pass must include the new line');
});

const ok = { ok: true, outcome: 'ok' };
const failed = { ok: false, outcome: 'lineFailed', error: 'controlled line failure' };
const probes = (c, start, line) => c.evidence.commands.slice(start)
  .filter(({ method, fields }) => method === 'probe' && fields.line === line).map(({ fields }) => fields.operator);
const healthLogs = (c) => c.evidence.logs.filter((line) => line.startsWith('LINE HEALTH '))
  .map((line) => JSON.parse(line.slice('LINE HEALTH '.length)));

async function pinnedController() {
  const c = controller();
  await c.apply();
  await c.api('lines/add', { alias: 'TestISP' });
  await c.api('app-line', { path: 'acceptance-app.exe', line: 'second' });
  await c.health();
  await c.health();
  return c;
}

test('health pairs stats with its revision while an add waits in the API queue', { timeout: 5000 }, async (t) => {
  const c = controller();
  await c.apply();
  await c.health();
  const entered = deferred(), release = deferred();
  c.setStats(async (snapshot) => { entered.resolve(); await release.promise; return snapshot; });
  const sampling = c.health();
  await entered.promise;
  const adding = c.api('lines/add', { alias: 'TestISP' });
  // Flush pending microtasks once, without a time-based race or retry loop.
  await nextTurn();
  const addWaitedForStats = c.saved.lines.length === 1 && c.saved.revision === 1;
  release.resolve();
  await Promise.all([sampling, adding]);
  await c.api('app-line', { path: 'acceptance-app.exe', line: 'second' });
  const second = c.saved.lines[1];
  t.diagnostic(JSON.stringify({ addWaitedForStats, revision: c.saved.revision, up: second.up, laneTarget: second.target }));
  assert.equal(addWaitedForStats, true, 'Stats and the selected revision must be read inside the API queue');
  assert.equal(second.up, true);
  assert.equal(second.target, 'second');
  assert.equal(c.saved.revision, 3);
  assert.deepEqual(c.evidence.errors, []);
});

test('health fences failed probe results after queued pin and line-order changes', { timeout: 5000 }, async (t) => {
  const c = await pinnedController();
  for (const [route, body] of [
    ['app-line', { path: 'acceptance-app.exe', line: 'main' }],
    ['lines/order', { ids: ['second', 'main'] }],
  ]) {
    const revision = c.saved.revision;
    const entered = deferred(), release = deferred(), queueEntered = deferred(), queueRelease = deferred();
    c.setProbe(async ({ line, operator }) => {
      if (line !== 'second') return ok;
      if (operator === 'quad9') { entered.resolve(); await release.promise; }
      return failed;
    });
    const sampling = c.health();
    await entered.promise;
    const blocker = c.enqueue(async () => { queueEntered.resolve(); await queueRelease.promise; });
    await queueEntered.promise;
    const changing = c.api(route, body);
    release.resolve();
    await nextTurn();
    // Establish that an outside-queue fence would still pass. The assertions
    // after releasing the queue check that only the API operation commits.
    assert.equal(c.saved.revision, revision);
    queueRelease.resolve();
    await Promise.all([blocker, changing, sampling]);
    const second = c.saved.lines.find(({ id }) => id === 'second');
    const discarded = healthLogs(c).at(-1);
    t.diagnostic(JSON.stringify({ route, revision: c.saved.revision, up: second.up, discarded }));
    assert.equal(second.up, true);
    assert.equal(c.saved.revision, revision + 1, 'Only the queued API change may apply');
    assert.equal(discarded.action, 'discard-stale');
    assert.equal(discarded.snapshotRevision, revision);
    assert.equal(discarded.revision, revision + 1);
    assert.deepEqual(discarded.probes.map(({ operator }) => operator), ['quick:cloudflare', 'google', 'quad9']);
  }
  assert.deepEqual(c.evidence.errors, []);
});

test('current interface, route, missing-binding and probe failures still fail over and recover', { timeout: 5000 }, async (t) => {
  const c = await pinnedController();
  const second = c.saved.lines[1];
  // All four outages and recoveries share one controller, pin and revision history.
  for (const reason of ['interface-down', 'no-default4', 'missing-binding', 'probe']) {
    const revision = c.saved.revision;
    c.setBinding('second', reason === 'missing-binding' ? null :
      { up: reason !== 'interface-down', default4: reason !== 'no-default4' });
    c.setProbe(async ({ line }) => line === 'second' && reason === 'probe' ? failed : ok);
    const start = c.evidence.commands.length;
    await c.health();
    const down = healthLogs(c).at(-1);
    assert.equal(second.up, false, reason);
    assert.equal(second.target, 'main', reason);
    assert.equal(c.saved.pins['acceptance-app.exe'], 'second', 'Failover must keep the pin');
    assert.equal(c.saved.revision, revision + 1);
    assert.equal(down.action, 'apply');
    assert.equal(down.reason, reason);
    assert.equal(down.bindingPresent, reason !== 'missing-binding');
    assert.deepEqual(probes(c, start, 'second'), reason === 'probe' ? ['quick:cloudflare', 'google', 'quad9'] : []);

    c.setBinding('second', {});
    // A passing quick probe alone still cannot recover a down line.
    c.setProbe(async ({ line, operator }) => line === 'second' && operator === 'cloudflare' ? failed : ok);
    const checking = c.evidence.commands.length;
    await c.health();
    assert.equal(second.up, false);
    assert.equal(c.saved.revision, revision + 1);
    assert.deepEqual(probes(c, checking, 'second'), ['quick:cloudflare', 'cloudflare']);
    // The full probe, not the quick result, determines recovery as before.
    c.setProbe(async ({ line, operator }) => line === 'second' && operator === 'quick:cloudflare' ? failed : ok);
    const recovering = c.evidence.commands.length;
    await c.health();
    assert.equal(second.up, true);
    assert.equal(second.target, 'second');
    assert.equal(c.saved.revision, revision + 2);
    assert.deepEqual(probes(c, recovering, 'second'), ['quick:cloudflare', 'cloudflare']);
    t.diagnostic(JSON.stringify({ reason, down, recovery: healthLogs(c).at(-1), revision: c.saved.revision }));
  }
  assert.deepEqual(c.evidence.errors, []);
});

test('each current line can fail and recover in one pass after the earlier line applies', { timeout: 5000 }, async (t) => {
  const c = await pinnedController();
  const revision = c.saved.revision;
  c.setBinding('main', { default4: false });
  c.setBinding('second', { up: false });
  await c.health();
  assert(c.saved.lines.every(({ up }) => up === false));
  assert.equal(c.saved.revision, revision + 2);
  c.setBinding('main', {});
  c.setBinding('second', {});
  await c.health();
  assert(c.saved.lines.every(({ up, id, target }) => up && id === target));
  assert.equal(c.saved.revision, revision + 4);
  assert.deepEqual(healthLogs(c).map(({ action }) => action), ['apply', 'apply', 'apply', 'apply']);
  assert.deepEqual(c.evidence.errors, []);
  t.diagnostic(JSON.stringify({ revision: c.saved.revision, changes: healthLogs(c) }));
});

test('stats and probe engine errors remain visible without becoming line failures', { timeout: 5000 }, async (t) => {
  const c = await pinnedController();
  const revision = c.saved.revision;
  c.setStats(async () => { throw new Error('controlled stats disconnect'); });
  await c.health();
  assert.match(c.evidence.errors.at(-1), /HEALTH ENGINE UNAVAILABLE .*controlled stats disconnect/);
  c.setStats(async (snapshot) => snapshot);
  c.setProbe(async ({ line }) => line === 'second' ?
    { ok: false, outcome: 'engineUnavailable', error: 'controlled socket capacity' } : ok);
  await c.health();
  assert.match(c.evidence.errors.at(-1), /HEALTH ENGINE UNAVAILABLE .*engineUnavailable.*controlled socket capacity/);
  c.setProbe(async ({ line }) => { if (line === 'second') throw new Error('controlled probe disconnect'); return ok; });
  await c.health();
  assert.match(c.evidence.errors.at(-1), /HEALTH ENGINE UNAVAILABLE .*command-error.*controlled probe disconnect/);
  assert.equal(c.evidence.errors.length, 3);
  assert(c.saved.lines.every(({ up, id, target }) => up && id === target));
  assert.equal(c.saved.revision, revision);
  assert.deepEqual(healthLogs(c), []);
  c.setProbe(async () => ok);
  await c.health();
  assert.equal(c.saved.revision, revision);
  t.diagnostic(JSON.stringify({ revision, errors: c.evidence.errors }));
});

test('a pending probe cannot commit across engine identity, epoch, stop or readiness changes', { timeout: 5000 }, async (t) => {
  const c = await pinnedController();
  const revision = c.saved.revision;
  for (const fields of [{ instance: 'engine-2' }, { epoch: 2 }, { stopping: true }, { ready: false }]) {
    const entered = deferred(), release = deferred();
    c.setProbe(async ({ line, operator }) => {
      if (line !== 'second') return ok;
      if (operator === 'quad9') { entered.resolve(); await release.promise; }
      return failed;
    });
    const sampling = c.health();
    await entered.promise;
    c.setSession(fields);
    release.resolve();
    await sampling;
    assert.equal(c.saved.lines[1].up, true);
    assert.equal(c.saved.revision, revision);
    assert.equal(healthLogs(c).at(-1).action, 'discard-stale');
    t.diagnostic(JSON.stringify({ fields, discarded: healthLogs(c).at(-1) }));
    c.setSession({ ready: true, stopping: false });
  }
  assert.deepEqual(c.evidence.errors, []);
});

test('an unacknowledged add cannot masquerade as a removed physical interface', { timeout: 5000 }, async (t) => {
  const c = controller();
  await c.apply();
  await c.health();
  c.setBeforeApply(async () => { throw new Error('controlled apply failure'); });
  await assert.rejects(c.api('lines/add', { alias: 'TestISP' }), /controlled apply failure/);
  assert.equal(c.saved.revision, 2);
  assert.equal(c.evidence.applies.length, 1, 'The native apply must actually be missing');
  await c.health();
  assert.equal(c.saved.lines[1].up, true);
  assert.equal(c.saved.revision, 2);
  assert.deepEqual(healthLogs(c), []);
  assert.match(c.evidence.errors.at(-1), /HEALTH ENGINE UNAVAILABLE .*not acknowledged/);
  c.setBeforeApply(async () => {});
  await c.api('app-line', { path: 'acceptance-app.exe', line: 'second' });
  const start = c.evidence.commands.length;
  await c.health();
  assert.deepEqual(probes(c, start, 'second'), ['quick:cloudflare']);
  assert.equal(c.saved.lines[1].target, 'second');
  assert.equal(c.saved.revision, 3);
  t.diagnostic(JSON.stringify({ revision: c.saved.revision, errors: c.evidence.errors, applies: c.evidence.applies.length }));
});
