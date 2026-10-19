import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { isDeepStrictEqual } from 'node:util';
import * as lines from '../../lib/lines.mjs';
import { appKey, AppTracker, OutsideTracker, mergeRows, parseOutsideId } from '../../lib/apps.mjs';
import { appPathPattern } from '../../lib/app-path.mjs';
import { periodStart, Usage } from '../../lib/usage.mjs';
import { offerFrom } from '../../lib/updates.mjs';
import { orderedPolicy } from '../oracle/ordered.mjs';

const binary = process.argv[2];
assert.ok(binary, 'Pass the compiled tests/differential/runner executable');
const seed = Number(process.env.ORACLE_SEED ?? 0x1234abcd) >>> 0;
let state = seed;
const random = () => { state ^= state << 13; state ^= state >>> 17; state ^= state << 5; return (state >>> 0) / 2 ** 32; };
const pick = (items) => items[Math.floor(random() * items.length)];
const number = (max) => Math.floor(random() * max);
const requests = [];
const expected = [];
const encode = (value) => value === undefined ? null : Array.isArray(value) ? value.map(encode)
  : value && typeof value === 'object' ? Object.fromEntries(Object.entries(value).map(([key, v]) => [key, encode(v)])) : value;
function add(name, args, result, extra = {}) { requests.push({ name, args, ...extra }); expected.push(encode(result)); }

for (const path of ['C:\\İΟΣ\\app-1.2\\App.exe', 'C:\\ΟΣΑ\\App.exe', 'C:\\Σ\\App.exe']) add('appKey', [path], appKey(path));
const edgeLabel = [{ id: 'a1', alias: 'Ethernet', label: 'a'.repeat(39) + '😀' }];
add('normalizeLines', [edgeLabel], lines.normalizeLines(edgeLabel));
for (const label of ['\ufeffPhone\ufeff', '\u0085Phone\u0085']) {
  const value = [{ id: 'a1', alias: 'Ethernet', label }];
  add('normalizeLines', [value], lines.normalizeLines(value));
}
for (const id of ['a1\n', 'a1\r\n', 'a1\u2028']) {
  const value = [{ id, alias: 'Ethernet' }];
  add('normalizeLines', [value], lines.normalizeLines(value));
}
for (const bytes of [0.49999999999999994, 9007199254740991, '0x10', '010', '1_0', [[2]], '\ufeff2\ufeff', '\u00852\u0085', 'inf', '-infinity', '+infinity', '0x1p3', '+0x10', '0x100000000000000000000', '1e400']) add('validCap', [{ bytes }], lines.validCap({ bytes }));
for (const end of ['\r', '\u2028', '\u2029', '\n']) {
  const id = `192.0.2.1:1>203.0.113.1:2|42|a${end}b`;
  add('parseOutsideId', [id], parseOutsideId(id));
}
for (const list of [[{ id: 'b2', weight: 1 }, { id: '10', weight: 3 }, { id: '2', weight: 2 }, { id: '01', weight: 1 }]]) {
  const shares = lines.sharesFromWeights(list, {});
  add('sharePorts', [list, {}], { shares, ports: lines.assignPorts(shares) });
}
{
  const input = { mainAlias: 'Ethernet', secondAlias: 'Wi-Fi', cableApps: ['c:\\apps\\x.exe'], secondApps: ['C:\\Apps\\X.exe'] };
  let entropy = 0;
  add('migrateSettings', [input], lines.migrateSettings(input, (size) => Buffer.alloc(size, ++entropy)));
  const pins = { 'C:\\Discord\\app-1.0.9\\Discord.exe': 'a1', 'C:\\Discord\\app-1.0.10\\Discord.exe': 'b2' };
  const waiting = ['C:\\Apps\\New.exe'];
  const next = lines.placeWaitingApps(waiting, pins, 'b2');
  add('placeWaitingApps', [waiting, pins, 'b2'], next);
  add('settingsPins', [pins, waiting], { appLines: next, rows: new AppTracker().snapshot(next) });
}
for (const [timezone, date] of [['America/Santiago', '2026-09-06'], ['America/Havana', '2026-03-08'], ['Africa/Cairo', '2026-04-24'], ['America/Havana', '2026-11-01']]) {
  process.env.TZ = timezone;
  const now = Date.parse(`${date}T12:00:00Z`);
  for (const cap of [{ period: 'day' }, { period: 'month', resetDay: new Date(now).getDate() }]) add('periodStart', [cap, now], periodStart(cap, now), { timezone });
}
for (const fields of [
  { mainAlias: 42, mainGuid: '', secondAlias: true, secondGuid: 7, secondLabel: 99, secondKind: false },
  { mainAlias: 'Ethernet', mainGuid: 7, secondAlias: 'Wi-Fi', secondGuid: '', secondLabel: 'Cable', secondKind: 2 },
  { secondAlias: 'Wi-Fi', secondLabel: { keep: true }, secondKind: null },
]) {
  let entropy = 0;
  add('migrateSettings', [fields], lines.migrateSettings(fields, (size) => Buffer.alloc(size, ++entropy)));
}
const savedUsage = { lines: { a1: { bytes: 3.5, periodStart: 1.5 }, b2: { bytes: 2, periodStart: 1e30 } }, peaks: {} };
add('usageLoad', [savedUsage], new Usage().load(savedUsage).toJSON());
for (const weight of ['Infinity', '-Infinity', 'NaN', 'Inf', '1e9999']) {
  const list = [{ id: 'a1' }, { id: 'b2' }];
  add('sharesFromWeights', [list, { a1: weight }], lines.sharesFromWeights(list, { a1: weight }));
}
for (let point = 0; point <= 0x10ffff; point++) {
  const char = String.fromCodePoint(point);
  if (/\p{Uppercase_Letter}|\p{Titlecase_Letter}/u.test(char)) {
    const path = `C:\\x${char}\\App.exe`;
    add('appKey', [path], appKey(path));
  }
}

for (let iteration = 0; iteration < 1000; iteration++) {
  const raw = Array.from({ length: number(9) }, (_, index) => ({
    id: pick([`a${index}`, `b${index}`, '', '../bad', 12]), alias: pick(['Ethernet', 'Wi-Fi', '', null]),
    label: pick(['  Phone  ', 'é'.repeat(number(60)), '日本語', null]),
    kind: pick(['wired', 'wifi', 'phone', 'other', null]), guid: pick([null, '', '{id}', 42]),
    strict: pick([true, false, 'true']), metered: pick([true, false, 1]), weight: pick([number(100), -1, '2', null]),
    cap: pick([null, { bytes: number(10000), period: pick(['day', 'month']), resetDay: number(32) }]),
  }));
  add('normalizeLines', [raw], lines.normalizeLines(raw));
  const cap = { bytes: pick([null, -1, 0, 0.4, 10.5, '123.4', true, false, [], [2], 'bad', number(1e9)]), period: pick(['day', 'month', 'bad']), resetDay: pick([0, 1, 15.9, '3', null, 31]) };
  add('validCap', [cap], lines.validCap(cap));
  const list = Array.from({ length: 1 + number(8) }, (_, index) => ({ id: `a${index}`, strict: random() < 0.3, weight: number(1000) }));
  const weights = Object.fromEntries(list.map((line) => [line.id, pick([0, 1, number(1e6), '4', null, -1])]));
  add('sharesFromWeights', [list, weights], lines.sharesFromWeights(list, weights));
  const up = Object.fromEntries(list.map((line) => [line.id, random() < 0.5]));
  const exhausted = list.filter(() => random() < 0.4).map((line) => line.id);
  const home = pick([...list.map((line) => line.id), 'missing']);
  add('laneTarget', [list, home, up, exhausted], lines.laneTarget(list, home, (id) => up[id], new Set(exhausted)));
  add('sharingLines', [list, exhausted], lines.sharingLines(list, new Set(exhausted)));
  const path = `C:\\${pick(['Apps', 'Apps (x86)', '日本語', 'a+b'])}\\${pick(['app-', 'v', '', 'release-'])}${number(100)}.${number(100)}.${number(100)}\\${pick(['App.exe', 'other.exe', 'a+b.exe'])}`;
  add('appKey', [path], appKey(path));
  add('appPathPattern', [path], appPathPattern(path));
  const outside = pick([`192.0.2.${number(255)}:${number(65536)}>203.0.113.1:443|${number(99999)}|2026-10-19T12:00:00Z`, '', '[::1]:1>x|1|y']);
  add('parseOutsideId', [outside], parseOutsideId(outside));
  const migration = { mainAlias: pick(['Ethernet', null]), secondAlias: pick(['Wi-Fi', null]), secondKind: pick(['phone', 'wifi', null]), secondApps: ['a.exe', 2], cableApps: ['b.exe'], lines: pick([[], [], [{ id: 'a1', alias: 'Ethernet' }]]) };
  let entropy = 0;
  add('migrateSettings', [migration], lines.migrateSettings(migration, (size) => Buffer.alloc(size, ++entropy)));
  const version = `${number(3)}.${number(20)}.${number(20)}`;
  const arch = pick(['x64', 'arm64', 'ia32']);
  const name = `NetSwitch-Setup-${version}-${arch}.exe`;
  const release = { tag_name: `v${version}`, html_url: pick([`https://github.com/AyoubAchour/net-switch/releases/tag/v${version}`, 'https://example.com/']), draft: random() < 0.1, prerelease: random() < 0.1, assets: [{ name, browser_download_url: `https://github.com/AyoubAchour/net-switch/releases/download/v${version}/${name}` }] };
  add('offerFrom', [release, '0.3.1', arch], offerFrom(release, '0.3.1', arch));
  const timezone = pick(['UTC', 'Europe/Paris', 'America/New_York', 'Australia/Sydney', 'America/Santiago', 'America/Havana', 'Africa/Cairo']);
  process.env.TZ = timezone;
  const now = Date.UTC(2026 + number(2), number(12), 1 + number(28), number(24));
  const period = { period: pick(['day', 'month']), resetDay: 1 + number(28) };
  add('periodStart', [period, now], periodStart(period, now), { timezone });
}
for (let i = 0; i < 400; i++) {
  const timezone = pick(['UTC', 'America/Santiago', 'America/Havana', 'Africa/Cairo']);
  process.env.TZ = timezone;
  const list = [{ id: 'a1', cap: { bytes: 1e7, period: 'day' } }, { id: 'b2', cap: { bytes: 1e6, period: 'month', resetDay: 6 } }];
  const saved = { peaks: { a1: 1e9 + random() * 1e7, b2: 1e8 }, lines: {} };
  const u = new Usage().load(structuredClone(saved));
  const steps = [], snapshots = [];
  let now = Date.parse('2026-09-06T03:59:50Z');
  for (let j = 0; j < 30; j++) {
    now += pick([number(8000), number(5000), 0, -number(1000)]);
    const counters = Object.fromEntries(list.map(({ id }) => [id, random() < 0.1 ? null : { rx: number(1e7), tx: number(1e6) }]));
    const rates = Object.fromEntries(list.map(({ id }) => [id, pick([null, 0, 300000 + number(1e7)])]));
    steps.push({ now, counters, rates });
    u.ingest(list, (l) => counters[l.id], (l) => rates[l.id], now);
    snapshots.push(structuredClone({ saved: u.toJSON(), exhausted: Object.fromEntries([...u.exhausted(list, now)].map((id) => [id, true])), weights: u.autoWeights(list) }));
  }
  add('usageSequence', [saved, list, steps], snapshots, { timezone });
}
for (let i = 0; i < 200; i++) {
  const tracker = new AppTracker();
  const outside = new OutsideTracker();
  const steps = [];
  const snapshots = [];
  const outsideSnapshots = [];
  for (let poll = 0; poll < 3; poll++) {
    const connections = Array.from({ length: 5 }, (_, index) => ({ id: String(index), metadata: { processPath: 'C:\\App.exe' }, chains: [`line-${pick(['a1', 'b2', 'c3', '123456', '012345'])}`], download: number(1e6) / 7, upload: number(1e4) / 13, start: '1970-01-01T00:00:00Z' }));
    const now = 1000 * (poll + 1);
    steps.push({ connections, now });
    tracker.ingest(connections, now);
    snapshots.push(tracker.snapshot());
    const samples = connections.map((c) => ({ id: c.id, path: c.metadata.processPath, line: c.chains[0].slice(5), down: c.download, up: c.upload, beforeRouting: true }));
    steps.at(-1).samples = samples;
    outside.ingest(samples, now);
    outsideSnapshots.push(mergeRows([], outside));
  }
  add('appSequence', [steps], snapshots);
  add('outsideSequence', [steps], outsideSnapshots);
}
const result = spawnSync(binary, [], { input: requests.map((request) => JSON.stringify(request)).join('\n') + '\n', encoding: 'utf8', maxBuffer: 32 * 1024 * 1024, timeout: 60_000, windowsHide: true });
assert.equal(result.status, 0, result.stderr);
const actual = result.stdout.trim().split('\n').map((line) => JSON.parse(line));
assert.equal(actual.length, requests.length);
const failures = [];
for (let i = 0; i < requests.length; i++) {
  const wanted = JSON.parse(JSON.stringify(expected[i]));
  const root = requests[i].name === 'sharesFromWeights' ? 'shares' : requests[i].name === 'placeWaitingApps' ? 'appLines' : '';
  if (!isDeepStrictEqual(orderedPolicy(actual[i], root), orderedPolicy(wanted, root))) failures.push({ seed, case: i, request: requests[i], actual: actual[i], expected: wanted });
}
assert.equal(failures.length, 0, JSON.stringify(failures.slice(0, 1), null, 2));
console.log(`${requests.length} differential cases passed; seed ${seed}; Node ${process.version}; Go runner ${binary}`);
