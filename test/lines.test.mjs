import assert from 'node:assert/strict';
import { test } from 'node:test';
import {
  assignPorts,
  FIRST_SHARED_PORT,
  isOpenLine,
  LAST_PORT,
  laneTarget,
  lineForPort,
  lineLabel,
  migrateSettings,
  newLine,
  normalizeLines,
  pickFirstAdapter,
  placeWaitingApps,
  sharesFromWeights,
  sharingLines,
  uniqueLabel,
  validCap,
} from '../lib/lines.mjs';

const adapter = (alias, kind, { metric = 25, routeMetric = 0, connected = true, virtual = false } = {}) => ({
  alias,
  kind,
  guid: `{${alias}}`,
  metric,
  routeMetric,
  connected,
  virtual,
});

test('a new line is named after what its adapter is, and a second of a kind gets a number', () => {
  assert.equal(lineLabel(adapter('Wi-Fi', 'wifi')), 'Wi-Fi');
  assert.equal(lineLabel(adapter('Ethernet 3', 'phone')), 'Phone');
  assert.equal(lineLabel(adapter('Ethernet', 'wired')), 'Cable');
  assert.equal(uniqueLabel('Wi-Fi', [{ label: 'Wi-Fi' }, { label: 'Wi-Fi 2' }]), 'Wi-Fi 3');
  const phone = newLine(adapter('Ethernet 3', 'phone'), [{ id: 'a1', label: 'Cable' }]);
  assert.match(phone.id, /^[0-9a-f]{6}$/);
  assert.notEqual(phone.id, 'a1');
  // A phone's data usually costs money.
  assert.deepEqual({ ...phone, id: null }, {
    id: null,
    alias: 'Ethernet 3',
    guid: '{Ethernet 3}',
    label: 'Phone',
    kind: 'phone',
    metered: true,
    strict: false,
    cap: null,
    weight: 1,
  });
});

test('the first line is whatever Windows uses for the internet now, wired or not; a cable wins a tie', () => {
  assert.equal(pickFirstAdapter([adapter('Ethernet', 'wired', { metric: 35 }), adapter('Wi-Fi', 'wifi', { metric: 25 })]).alias, 'Wi-Fi');
  assert.equal(pickFirstAdapter([adapter('Wi-Fi', 'wifi'), adapter('Ethernet', 'wired')]).alias, 'Ethernet');
  assert.equal(
    pickFirstAdapter([adapter('vEthernet', 'wired', { metric: 5, virtual: true }), adapter('Wi-Fi', 'wifi', { connected: false })]),
    null,
  );
});

test('0.2.0 settings become two lines, with every app choice kept', () => {
  const changes = migrateSettings({
    mainAlias: 'Ethernet',
    mainGuid: '{e}',
    secondAlias: 'Wi-Fi',
    secondGuid: '{w}',
    secondLabel: 'Wi-Fi stick',
    secondKind: 'wifi',
    secondApps: ['C:\\Games\\steam.exe'],
    cableApps: ['C:\\Discord\\Discord.exe'],
    combine: true,
  });
  const [cable, stick] = changes.lines;
  assert.deepEqual([cable.alias, cable.guid, cable.label, cable.kind], ['Ethernet', '{e}', 'Cable', 'wired']);
  assert.deepEqual([stick.alias, stick.guid, stick.label, stick.kind, stick.metered], ['Wi-Fi', '{w}', 'Wi-Fi stick', 'wifi', false]);
  assert.deepEqual(changes.appLines, { 'C:\\Games\\steam.exe': stick.id, 'C:\\Discord\\Discord.exe': cable.id });
  // The old keys are removed; combining is left as it was.
  for (const key of ['mainAlias', 'mainGuid', 'secondAlias', 'secondGuid', 'secondLabel', 'secondKind', 'secondApps', 'cableApps']) {
    assert.ok(Object.hasOwn(changes, key) && changes[key] === undefined, key);
  }
  assert.equal(Object.hasOwn(changes, 'combine'), false);

  // A second connection that had been removed: its apps wait for the next line.
  const removed = migrateSettings({ mainAlias: 'Ethernet', secondAlias: null, secondApps: ['C:\\Games\\steam.exe'] });
  assert.equal(removed.lines.length, 1);
  assert.deepEqual(removed.waitingApps, ['C:\\Games\\steam.exe']);
  assert.equal(migrateSettings({ mainAlias: 'Ethernet', secondAlias: 'Wi-Fi', secondApps: ['a.exe'] }).waitingApps, undefined);
  assert.deepEqual(placeWaitingApps(['C:\\Games\\steam.exe', 'C:\\Kept.exe'], { 'c:\\kept.exe': 'a1' }, 'b2'), {
    'c:\\kept.exe': 'a1',
    'C:\\Games\\steam.exe': 'b2',
  });
  assert.equal(placeWaitingApps(undefined, {}, 'b2'), null);
  // A phone as the second connection counts as metered.
  assert.equal(migrateSettings({ mainAlias: 'Ethernet', secondAlias: 'Ethernet 3', secondKind: 'phone' }).lines[1].metered, true);
  // Only a cable: one line.
  assert.equal(migrateSettings({ mainAlias: 'Ethernet', secondAlias: null }).lines.length, 1);
  // Loaded settings come with the default empty list of lines: still migrated.
  assert.equal(migrateSettings({ lines: [], mainAlias: 'Ethernet' }).lines[0].alias, 'Ethernet');
  // Nothing to migrate.
  assert.equal(migrateSettings({ lines: [{ id: 'a1', alias: 'Ethernet' }], mainAlias: 'Ethernet' }), null);
  assert.equal(migrateSettings({ lines: [], mainAlias: null, secondAlias: null }), null);
});

test('lines from the settings file are repaired or dropped, and the main line is never kept to its own apps', () => {
  const lines = normalizeLines([
    { id: 'a1', alias: 'Ethernet', strict: true, label: '  Fibre  ', cap: { bytes: 0 } },
    { id: 'a1', alias: 'Duplicate' },
    { id: '../../evil', alias: 'Wi-Fi' },
    { id: 'b2', alias: '' },
    { id: 'c3', alias: 'Ethernet 3', kind: 'phone', metered: true, strict: true, weight: -2, cap: { bytes: 5e9, period: 'day' } },
    // A number id would give the same tags and file names as its text.
    { id: 12, alias: 'Number' },
    'Wi-Fi',
  ]);
  assert.deepEqual(lines, [
    { id: 'a1', alias: 'Ethernet', guid: null, label: 'Fibre', kind: null, metered: false, strict: false, cap: null, weight: 1 },
    {
      id: 'c3',
      alias: 'Ethernet 3',
      guid: null,
      label: 'Ethernet 3',
      kind: 'phone',
      metered: true,
      strict: true,
      cap: { bytes: 5e9, period: 'day' },
      weight: 1,
    },
  ]);
  assert.deepEqual(normalizeLines(null), []);
});

test('a data cap is an amount per day, or per month from a reset day', () => {
  assert.deepEqual(validCap({ bytes: 10.4, period: 'month' }), { bytes: 10, period: 'month', resetDay: 1 });
  assert.deepEqual(validCap({ bytes: 10, period: 'month', resetDay: 15 }), { bytes: 10, period: 'month', resetDay: 15 });
  assert.deepEqual(validCap({ bytes: 10, resetDay: 31 }), { bytes: 10, period: 'month', resetDay: 1 });
  assert.deepEqual(validCap({ bytes: 10, period: 'day', resetDay: 3 }), { bytes: 10, period: 'day' });
  assert.equal(validCap({ bytes: -1 }), null);
  assert.equal(validCap({ bytes: 'lots' }), null);
  assert.equal(validCap(null), null);
});

const LINES = [
  { id: 'a1', strict: false },
  { id: 'b2', strict: false },
  { id: 'c3', strict: true },
  { id: 'd4', strict: false },
];

test('a line’s apps use it while it is up, else the first other line that is up and may take them', () => {
  const up = (...ids) => (id) => ids.includes(id);
  assert.equal(laneTarget(LINES, 'b2', up('a1', 'b2')), 'b2');
  assert.equal(laneTarget(LINES, 'b2', up('a1')), 'a1');
  // c3 is kept to its own apps: it never takes over for another line.
  assert.equal(laneTarget(LINES, 'b2', up('c3', 'd4')), 'd4');
  // But its own apps do move when it is down.
  assert.equal(laneTarget(LINES, 'c3', up('a1')), 'a1');
  // Nowhere better: they stay.
  assert.equal(laneTarget(LINES, 'b2', up('c3')), 'b2');
  // A line out of data counts as down, for its own apps too.
  assert.equal(laneTarget(LINES, 'b2', up('a1', 'b2', 'd4'), new Set(['b2', 'a1'])), 'd4');
  assert.equal(laneTarget(LINES, 'zz', up('a1')), null);
});

test('every open line takes part in combining, the main line too until it is out of data', () => {
  assert.deepEqual(sharingLines(LINES).map((line) => line.id), ['a1', 'b2', 'd4']);
  // Out of data, the main line leaves sharing rather than handing its share on.
  assert.deepEqual(sharingLines(LINES, new Set(['a1', 'b2'])).map((line) => line.id), ['d4']);
  assert.deepEqual(sharingLines([{ id: 'a1', strict: true }, ...LINES.slice(1)]).map((line) => line.id), ['a1', 'b2', 'd4']);
  assert.equal(isOpenLine(LINES[2]), false);
});

test('shares follow the weights in 5% steps, and every sharing line keeps at least one step', () => {
  const lines = [{ id: 'a1' }, { id: 'b2' }, { id: 'c3' }];
  assert.deepEqual(sharesFromWeights(lines.slice(0, 2), { a1: 1, b2: 1 }), { a1: 0.5, b2: 0.5 });
  assert.deepEqual(sharesFromWeights(lines.slice(0, 2), { a1: 3, b2: 1 }), { a1: 0.75, b2: 0.25 });
  assert.deepEqual(sharesFromWeights(lines, {}), { a1: 0.35, b2: 0.35, c3: 0.3 });
  assert.deepEqual(sharesFromWeights(lines, { a1: 100, b2: 0, c3: 0 }), { a1: 0.9, b2: 0.05, c3: 0.05 });
  assert.deepEqual(sharesFromWeights(lines, { a1: 0, b2: 0, c3: 0 }), { a1: 0.35, b2: 0.35, c3: 0.3 });
  // A line's own weight is the fallback.
  assert.deepEqual(sharesFromWeights([{ id: 'a1', weight: 1 }, { id: 'b2', weight: 4 }]), { a1: 0.2, b2: 0.8 });
  assert.deepEqual(sharesFromWeights([]), {});
  for (const weights of [{ a1: 1, b2: 2, c3: 3 }, { a1: 7, b2: 0.1, c3: 0.1 }, { a1: 1e9, b2: 1, c3: 1 }]) {
    const shares = sharesFromWeights(lines, weights);
    const steps = Object.values(shares).map((share) => Math.round(share * 20));
    assert.equal(steps.reduce((sum, step) => sum + step, 0), 20, JSON.stringify(weights));
    assert.ok(steps.every((step) => step >= 1), JSON.stringify(weights));
  }
});

// How many of n connections from consecutive ports, `step` apart, each line gets.
function burst(shares, start, step, n) {
  const entries = Object.entries(shares);
  const counts = Object.fromEntries(entries.map(([id]) => [id, 0]));
  for (let i = 0; i < n; i += 1) counts[lineForPort(start + i * step, entries)] += 1;
  return counts;
}

test('every port goes to exactly one line, and each line gets its share of them', () => {
  const shares = { a1: 0.5, b2: 0.3, c3: 0.2 };
  const ports = assignPorts(shares);
  const all = Object.values(ports).flat().sort((x, y) => x - y);
  assert.equal(all.length, LAST_PORT - FIRST_SHARED_PORT + 1);
  assert.equal(all[0], FIRST_SHARED_PORT);
  assert.equal(new Set(all).size, all.length);
  for (const [id, share] of Object.entries(shares)) {
    assert.ok(Math.abs(ports[id].length / all.length - share) < 0.001, id);
  }
});

test('any eight connections 1, 2 or 4 ports apart split close to the shares', () => {
  // Windows hands ports out in order: one after another for a burst, every
  // other one when the engine's own socket follows each app connection.
  for (const [shares, worst] of [
    [{ a1: 0.5, b2: 0.5 }, 1],
    [{ a1: 0.75, b2: 0.25 }, 2],
  ]) {
    for (const step of [1, 2, 4]) {
      for (let start = FIRST_SHARED_PORT; start + 7 * step <= LAST_PORT; start += 1) {
        const counts = burst(shares, start, step, 8);
        for (const [id, share] of Object.entries(shares)) {
          assert.ok(Math.abs(counts[id] - share * 8) <= worst, `${JSON.stringify(shares)} step ${step} from ${start}: ${JSON.stringify(counts)}`);
        }
      }
    }
  }
});

test('the ports Windows handed out on this PC split four and four', () => {
  const shares = { a1: 0.5, b2: 0.5 };
  // Eight connections through the TUN, each followed by the engine's own socket.
  const throughTun = [64393, 64395, 64397, 64399, 64401, 64403, 64405, 64407];
  // Eight parallel downloads through the test-mode proxy.
  const throughProxy = [49673, 49674, 49675, 49676, 49677, 49678, 49680, 49681];
  for (const ports of [throughTun, throughProxy]) {
    const counts = { a1: 0, b2: 0 };
    for (const port of ports) counts[lineForPort(port, Object.entries(shares))] += 1;
    assert.ok(Math.abs(counts.a1 - 4) <= 1, JSON.stringify(counts));
  }
});
