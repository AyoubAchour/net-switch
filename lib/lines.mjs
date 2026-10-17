// The lines Net Switch routes through, and the decisions that depend only on
// them: where an app's traffic goes, which line takes over for one that is
// down, and how combining shares new connections. Pure: no I/O, so every rule
// here can be tested with plain objects.
import { randomBytes } from 'node:crypto';
import { effectiveMetric } from './network.mjs';

// A short id per line, kept when Windows renames its adapter.
export function newLineId(taken = []) {
  for (;;) {
    const id = randomBytes(3).toString('hex');
    if (!taken.includes(id)) return id;
  }
}

// What a line is called in the window, from what its adapter is.
export function lineLabel(adapter) {
  if (!adapter) return 'Connection';
  if (adapter.kind === 'wifi') return 'Wi-Fi';
  if (adapter.kind === 'phone') return 'Phone';
  if (adapter.kind === 'wired') return 'Cable';
  return adapter.alias;
}

// A label that no other line uses yet: a second Wi-Fi becomes "Wi-Fi 2".
export function uniqueLabel(label, lines) {
  const used = new Set(lines.map((line) => line.label));
  if (!used.has(label)) return label;
  for (let n = 2; ; n += 1) if (!used.has(`${label} ${n}`)) return `${label} ${n}`;
}

export function newLine(adapter, lines) {
  return {
    id: newLineId(lines.map((line) => line.id)),
    alias: adapter.alias,
    guid: adapter.guid || null,
    label: uniqueLabel(lineLabel(adapter), lines),
    kind: adapter.kind ?? null,
    metered: adapter.kind === 'phone',
    strict: false,
    cap: null,
    weight: 1,
  };
}

// The adapter Windows sends internet traffic through now, for a first line:
// connected, real, with a default route, the lowest route metric first. Wired
// adapters win a tie, since they are usually the steady line.
export function pickFirstAdapter(adapters) {
  const usable = adapters.filter((adapter) => adapter.connected && !adapter.virtual);
  usable.sort(
    (a, b) => effectiveMetric(a) - effectiveMetric(b) || Number(b.kind === 'wired') - Number(a.kind === 'wired'),
  );
  return usable[0] ?? null;
}

// Line ids end up in rule file names and engine tags, so only short hex ids
// are accepted from the settings file.
const LINE_ID = /^[0-9a-f]{1,16}$/;
export const MAX_LABEL_LENGTH = 40;

// A data cap as saved: { bytes, period: 'day' | 'month', resetDay } or null.
export function validCap(cap) {
  if (!cap || typeof cap !== 'object') return null;
  const bytes = Number(cap.bytes);
  if (!Number.isFinite(bytes) || bytes <= 0) return null;
  if (cap.period === 'day') return { bytes: Math.round(bytes), period: 'day' };
  const resetDay = Math.trunc(Number(cap.resetDay ?? 1));
  return { bytes: Math.round(bytes), period: 'month', resetDay: resetDay >= 1 && resetDay <= 28 ? resetDay : 1 };
}

// The lines from the settings file, with anything a hand edit or an older
// version may have left out filled in, and anything unusable dropped. The main
// line can't be kept to its own apps: everything without a choice uses it.
export function normalizeLines(lines) {
  const result = [];
  for (const raw of Array.isArray(lines) ? lines : []) {
    // A number id would read the same as its text in tags and file names.
    if (!raw || typeof raw !== 'object' || typeof raw.id !== 'string' || !LINE_ID.test(raw.id)) continue;
    if (typeof raw.alias !== 'string' || !raw.alias) continue;
    if (result.some((line) => line.id === raw.id)) continue;
    const label = typeof raw.label === 'string' && raw.label.trim() ? raw.label.trim().slice(0, MAX_LABEL_LENGTH) : raw.alias;
    result.push({
      id: raw.id,
      alias: raw.alias,
      guid: typeof raw.guid === 'string' && raw.guid ? raw.guid : null,
      label,
      kind: ['wired', 'wifi', 'phone'].includes(raw.kind) ? raw.kind : null,
      metered: raw.metered === true,
      strict: raw.strict === true && result.length > 0,
      cap: validCap(raw.cap),
      weight: Number.isFinite(raw.weight) && raw.weight >= 0 ? raw.weight : 1,
    });
  }
  return result;
}

// Settings from 0.2.0 and earlier knew exactly two lines: the cable (main) and
// an optional second connection, with apps listed on the second line or kept
// on the cable. Returns the changes that turn them into lines, or null when
// there is nothing to migrate. Loaded settings always have a list of lines
// (the default is empty), so only lines that are really there mean the
// migration already happened.
export function migrateSettings(values) {
  if ((Array.isArray(values.lines) && values.lines.length > 0) || (!values.mainAlias && !values.secondAlias)) return null;
  const lines = [];
  if (values.mainAlias) {
    lines.push({
      id: newLineId(),
      alias: values.mainAlias,
      guid: values.mainGuid ?? null,
      label: 'Cable',
      kind: 'wired',
      metered: false,
      strict: false,
      cap: null,
      weight: 1,
    });
  }
  if (values.secondAlias) {
    lines.push({
      id: newLineId(lines.map((line) => line.id)),
      alias: values.secondAlias,
      guid: values.secondGuid ?? null,
      label: uniqueLabel(values.secondLabel || 'Second connection', lines),
      kind: values.secondKind ?? null,
      metered: values.secondKind === 'phone',
      strict: false,
      cap: null,
      weight: 1,
    });
  }
  const appLines = {};
  const second = values.secondAlias ? lines[lines.length - 1].id : null;
  const main = values.mainAlias ? lines[0].id : null;
  const secondApps = Array.isArray(values.secondApps) ? values.secondApps.filter((path) => typeof path === 'string') : [];
  for (const path of Array.isArray(values.cableApps) ? values.cableApps : []) if (main) appLines[path] = main;
  for (const path of secondApps) if (second) appLines[path] = second;
  // 0.2.0 kept the second connection's apps when it was removed, and they
  // went back to the next one chosen: they wait for the next line added.
  const waitingApps = !second && secondApps.length > 0 ? secondApps : undefined;
  return { lines, appLines, waitingApps, ...withoutLegacyKeys() };
}

// Apps waiting for a line (see migrateSettings) go to a new line that isn't
// the main one, unless they have a line already. Returns the new app choices,
// or null when nothing changes.
export function placeWaitingApps(waitingApps, appLines, lineId) {
  if (!Array.isArray(waitingApps) || waitingApps.length === 0) return null;
  const next = { ...appLines };
  const pinned = new Set(Object.keys(appLines).map((path) => path.toLowerCase()));
  for (const path of waitingApps) if (typeof path === 'string' && !pinned.has(path.toLowerCase())) next[path] = lineId;
  return next;
}

// The settings keys of 0.2.0 and earlier, removed once they are lines: set to
// undefined, which Settings.update removes.
export const LEGACY_KEYS = [
  'mainAlias',
  'mainGuid',
  'secondAlias',
  'secondGuid',
  'secondLabel',
  'secondKind',
  'secondApps',
  'cableApps',
];
export function withoutLegacyKeys() {
  return Object.fromEntries(LEGACY_KEYS.map((key) => [key, undefined]));
}

// Lines that may carry other lines' traffic: not kept to their own apps
// ("only apps I choose") and not out of data for this period.
export function isOpenLine(line, exhausted = new Set()) {
  return !line.strict && !exhausted.has(line.id);
}

// Where a line's apps go now: home while it is up; else the first other line,
// in priority order, that is up and may carry other lines' traffic; else home
// again, since there is nowhere better. up(id) says whether a line is up. A
// line that is out of data counts as down for its own apps too.
export function laneTarget(lines, lineId, up, exhausted = new Set()) {
  const own = lines.find((line) => line.id === lineId);
  if (!own) return null;
  if (up(lineId) && !exhausted.has(lineId)) return lineId;
  const other = lines.find((line) => line.id !== lineId && up(line.id) && isOpenLine(line, exhausted));
  return other ? other.id : lineId;
}

// Lines that take part in combining: every open line. The main line can't be
// kept to its own apps, but it leaves sharing too once it is out of data,
// rather than passing its share on to the line standing in for it.
export function sharingLines(lines, exhausted = new Set()) {
  return lines.filter((line, index) => (index === 0 ? !exhausted.has(line.id) : isOpenLine(line, exhausted)));
}

// Shares (0..1, summing to 1) from weights, in 5% steps so the rule files
// don't change for tiny measurement differences. Every sharing line keeps at
// least one step.
export const SHARE_STEP = 0.05;
export function sharesFromWeights(lines, weights = {}) {
  if (lines.length === 0) return {};
  const steps = Math.round(1 / SHARE_STEP);
  const raw = lines.map((line) => Math.max(0, Number(weights[line.id] ?? line.weight ?? 1) || 0));
  const total = raw.reduce((sum, value) => sum + value, 0);
  // All zero means no preference: equal shares.
  const exact = raw.map((value) => (total > 0 ? (value / total) * steps : steps / lines.length));
  const counts = exact.map((value) => Math.max(1, Math.floor(value)));
  // Largest remainder first gets the steps rounding left over; a line that
  // got its minimum step at another's expense gives it back from the smallest.
  const byRemainder = exact.map((value, index) => [value - Math.floor(value), index]).sort((a, b) => b[0] - a[0]);
  let left = steps - counts.reduce((sum, value) => sum + value, 0);
  for (let i = 0; left > 0; i = (i + 1) % byRemainder.length, left -= 1) counts[byRemainder[i][1]] += 1;
  const bySize = counts.map((count, index) => [count, index]).sort((a, b) => b[0] - a[0]);
  for (let i = 0; left < 0 && i < bySize.length * steps; i += 1) {
    const index = bySize[i % bySize.length][1];
    if (counts[index] > 1) {
      counts[index] -= 1;
      left += 1;
    }
  }
  return Object.fromEntries(lines.map((line, index) => [line.id, counts[index] / steps]));
}

// Combining picks a line for each new connection by its source port. Windows
// hands ports out in order (one after another for a burst, every other one
// when each app connection is followed by the engine's own), so neighbouring
// ports must spread over the lines in proportion. Each port gets a position in
// [0, 1) from the golden ratio, whose multiples are spread evenly for any
// step between ports; each line owns a slice of [0, 1) as wide as its share.
export const FIRST_SHARED_PORT = 1024;
export const LAST_PORT = 65535;
const GOLDEN = 0.6180339887498949;

export function portPosition(port) {
  return (port * GOLDEN) % 1;
}

// Which line a port goes to, given [[lineId, share], ...] in line order.
export function lineForPort(port, shares) {
  const position = portPosition(port);
  let edge = 0;
  for (const [id, share] of shares) {
    edge += share;
    if (position < edge) return id;
  }
  return shares[shares.length - 1][0];
}

// The ports each sharing line gets: { [lineId]: [ports...] }.
export function assignPorts(shares) {
  const entries = Object.entries(shares);
  const ports = Object.fromEntries(entries.map(([id]) => [id, []]));
  if (entries.length === 0) return ports;
  for (let port = FIRST_SHARED_PORT; port <= LAST_PORT; port += 1) ports[lineForPort(port, entries)].push(port);
  return ports;
}
