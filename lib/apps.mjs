// Turns the engine's connection list into per-app speeds, per line.
// Pure logic: no I/O, so it can be tested with plain objects.
import { normalizedAppPath } from './app-path.mjs';

export const UNKNOWN_APP = 'unknown';

// Each line's outbound in the engine, and the selector its traffic goes
// through so Net Switch can point it at another line while it is down.
export function lineOutbound(lineId) {
  return `line-${lineId}`;
}
export function laneSelector(lineId) {
  return `lane-${lineId}`;
}

const IDLE_KEEP_MS = 10 * 60_000;
const DISPLAY_SMOOTHING = 0.6;
const SORT_SMOOTHING = 0.25;

export function appKey(processPath, platform) {
  return processPath ? normalizedAppPath(processPath, platform) : UNKNOWN_APP;
}

// Older settings may pin several versions of an app. Keep the last saved
// choice everywhere, so the window and the engine agree without a migration.
export function appPins(appLines = {}, platform) {
  return new Map(Object.entries(appLines).map(([path, lineId]) => [appKey(path, platform), { path, lineId }]));
}

// The line that carries a connection: chains[0] is the outbound that really
// carries it, even when it went through another line's selector. Null for
// anything that isn't a line's outbound.
export function connectionLine(connection) {
  const tag = connection?.chains?.[0];
  return typeof tag === 'string' && tag.startsWith('line-') ? tag.slice('line-'.length) : null;
}

// Per-line numbers are kept in plain objects keyed by line id, so any number
// of lines works and a line that has nothing yet simply isn't there.
function addTo(rates, lineId, down, up) {
  const rate = (rates[lineId] ??= { down: 0, up: 0 });
  rate.down += down;
  rate.up += up;
}

function total(rates, field) {
  return Object.values(rates).reduce((sum, rate) => sum + rate[field], 0);
}

function downOnly(rates) {
  return Object.fromEntries(Object.entries(rates).map(([lineId, rate]) => [lineId, rate.down]));
}

function smoothRates(before, now, seconds, weight) {
  const lineIds = new Set([...Object.keys(before ?? {}), ...Object.keys(now)]);
  const result = {};
  for (const lineId of lineIds) {
    const down = seconds && now[lineId] ? now[lineId].down / seconds : 0;
    const up = seconds && now[lineId] ? now[lineId].up / seconds : 0;
    const smoothed = {
      down: smooth(before?.[lineId]?.down ?? 0, down, weight),
      up: smooth(before?.[lineId]?.up ?? 0, up, weight),
    };
    if (smoothed.down > 0 || smoothed.up > 0 || now[lineId]) result[lineId] = smoothed;
  }
  return result;
}

export class AppTracker {
  constructor({ idleKeepMs = IDLE_KEEP_MS, platform } = {}) {
    this.platform = platform;
    this.idleKeepMs = idleKeepMs;
    this.previousBytes = new Map();
    this.apps = new Map();
    // Routed bytes per second arriving through each line, from the last poll.
    this.lineRates = {};
    this.lastPollAt = null;
  }

  reset() {
    this.previousBytes.clear();
    for (const app of this.apps.values()) {
      app.lines = {};
      app.sortScore = 0;
      app.connections = {};
      app.ids = {};
    }
    this.lineRates = {};
    this.lastPollAt = null;
  }

  // A line's routed speed, { down, up }, zero when it carried nothing.
  lineRate(lineId) {
    return this.lineRates[lineId] ?? { down: 0, up: 0 };
  }

  ingest(connections, now) {
    const seconds = this.lastPollAt === null ? null : Math.max((now - this.lastPollAt) / 1000, 0.2);
    const nextBytes = new Map();
    const perApp = new Map();
    const lineBytes = {};

    for (const connection of connections) {
      const path = connection.metadata?.processPath || '';
      const key = appKey(path, this.platform);
      const lineId = connectionLine(connection) ?? 'unknown';
      const previous = this.previousBytes.get(connection.id);
      let down = 0;
      let up = 0;
      if (previous) {
        down = Math.max(0, connection.download - previous.download);
        up = Math.max(0, connection.upload - previous.upload);
      } else if (this.lastPollAt !== null && Date.parse(connection.start) >= this.lastPollAt - 2000) {
        // Opened since the last poll: all of its bytes are new.
        down = connection.download;
        up = connection.upload;
      }
      nextBytes.set(connection.id, { download: connection.download, upload: connection.upload });

      let entry = perApp.get(key);
      if (!entry) {
        entry = { path, lines: {}, connections: {}, ids: {} };
        perApp.set(key, entry);
      }
      addTo(entry.lines, lineId, down, up);
      entry.connections[lineId] = (entry.connections[lineId] ?? 0) + 1;
      (entry.ids[lineId] ??= []).push(connection.id);
      addTo(lineBytes, lineId, down, up);
    }

    for (const [key, entry] of perApp) {
      if (!this.apps.has(key)) {
        this.apps.set(key, { key, path: entry.path, lines: {}, sortScore: 0, lastSeen: now, connections: {}, ids: {} });
      }
    }

    for (const app of this.apps.values()) {
      const entry = perApp.get(app.key);
      const raw = entry ? entry.lines : {};
      app.lines = smoothRates(app.lines, raw, seconds, DISPLAY_SMOOTHING);
      const sum = seconds ? (total(raw, 'down') + total(raw, 'up')) / seconds : 0;
      app.sortScore = smooth(app.sortScore, sum, SORT_SMOOTHING);
      app.connections = entry ? entry.connections : {};
      app.ids = entry ? entry.ids : {};
      if (entry) {
        app.lastSeen = now;
        // After an update, use the current file for names, icons and actions.
        app.path = entry.path;
      }
    }

    for (const [key, app] of this.apps) {
      const idle = Object.values(app.connections).every((count) => count === 0);
      if (idle && now - app.lastSeen > this.idleKeepMs) this.apps.delete(key);
    }

    this.lineRates = {};
    for (const [lineId, bytes] of Object.entries(lineBytes)) {
      this.lineRates[lineId] = { down: seconds ? bytes.down / seconds : 0, up: seconds ? bytes.up / seconds : 0 };
    }

    this.previousBytes = nextBytes;
    this.lastPollAt = now;
  }

  // Apps to show: active ones, recently active ones, and every app the person
  // pinned to a line (even if it is not running right now). appLines:
  // { programPath: lineId }.
  snapshot(appLines = {}) {
    const pinned = appPins(appLines, this.platform);
    const rows = [...this.apps.values()];
    for (const [key, { path }] of pinned) {
      if (!this.apps.has(key)) rows.push({ key, path, lines: {}, sortScore: 0, connections: {} });
    }
    return rows.map((app) => ({
      key: app.key,
      path: app.path,
      line: pinned.get(app.key)?.lineId ?? null,
      rate: { down: total(app.lines, 'down'), up: total(app.lines, 'up') },
      lineDown: downOnly(app.lines),
      sortScore: app.sortScore,
      connections: { ...app.connections },
    }));
  }

  // Engine connection ids of one app on one line, from the latest poll.
  connectionIdsFor(key, lineId) {
    return [...(this.apps.get(key)?.ids?.[lineId] ?? [])];
  }

  // Engine connection ids of one app on every line but the given one.
  connectionIdsOffLine(key, lineId) {
    const ids = this.apps.get(key)?.ids ?? {};
    return Object.entries(ids).flatMap(([id, list]) => (id === lineId ? [] : list));
  }
}

// Connections that go around the routing engine (for example a download that
// was already running when routing started), measured from Windows'
// per-connection byte counts. Same smoothing as routed traffic.
export class OutsideTracker {
  constructor({ platform } = {}) {
    this.platform = platform;
    this.previousBytes = new Map();
    this.apps = new Map();
    this.lastAt = null;
  }

  reset() {
    this.previousBytes.clear();
    this.apps.clear();
    this.lastAt = null;
  }

  // samples: [{ id, path, line, down, up, beforeRouting }]; line is the line
  // whose address the connection uses; down/up are byte totals, or null when
  // Windows could not measure that connection.
  ingest(samples, now) {
    const seconds = this.lastAt === null ? null : Math.max((now - this.lastAt) / 1000, 0.2);
    const nextBytes = new Map();
    const perApp = new Map();
    for (const sample of samples) {
      const key = appKey(sample.path, this.platform);
      let entry = perApp.get(key);
      if (!entry) {
        entry = { path: sample.path ?? '', lines: {}, connections: 0, beforeRouting: true, measured: false, ids: [] };
        perApp.set(key, entry);
      }
      entry.connections += 1;
      entry.ids.push({ id: sample.id, line: sample.line });
      entry.beforeRouting = entry.beforeRouting && sample.beforeRouting;
      if (sample.down === null || sample.down === undefined) continue;
      entry.measured = true;
      const previous = this.previousBytes.get(sample.id);
      if (previous) addTo(entry.lines, sample.line, Math.max(0, sample.down - previous.down), Math.max(0, sample.up - previous.up));
      nextBytes.set(sample.id, { down: sample.down, up: sample.up });
    }

    const apps = new Map();
    for (const [key, entry] of perApp) {
      const before = this.apps.get(key);
      const sum = seconds ? (total(entry.lines, 'down') + total(entry.lines, 'up')) / seconds : 0;
      apps.set(key, {
        key,
        path: entry.path,
        lines: smoothRates(before?.lines, entry.lines, seconds, DISPLAY_SMOOTHING),
        connections: entry.connections,
        beforeRouting: entry.beforeRouting,
        measured: entry.measured,
        ids: entry.ids,
        sortScore: smooth(before?.sortScore ?? 0, sum, SORT_SMOOTHING),
      });
    }
    this.apps = apps;
    this.previousBytes = nextBytes;
    this.lastAt = now;
  }

  get(key) {
    return this.apps.get(key) ?? null;
  }

  entries() {
    return [...this.apps.values()];
  }

  // Outside connection ids of one app that are not on the given line.
  idsOffLine(key, lineId) {
    return (this.apps.get(key)?.ids ?? []).filter((item) => item.line !== lineId).map((item) => item.id);
  }

  // Every outside connection id of one app, on any line.
  idsOf(key) {
    return (this.apps.get(key)?.ids ?? []).map((item) => item.id);
  }
}

// Outside connection ids look like "local:port>remote:port|pid|created".
export function parseOutsideId(id) {
  const match = /^(\d+\.\d+\.\d+\.\d+):(\d+)>(\d+\.\d+\.\d+\.\d+):(\d+)\|(\d+)\|(.+)$/.exec(id ?? '');
  if (!match) return null;
  return {
    local: match[1],
    lport: Number(match[2]),
    remote: match[3],
    rport: Number(match[4]),
    pid: Number(match[5]),
    created: match[6],
  };
}

// One row per app: routed traffic from the engine plus traffic that goes around it.
export function mergeRows(routedRows, outside, appLines = {}, platform) {
  const pinned = appPins(appLines, platform);
  const rows = new Map(routedRows.map((row) => [row.key, row]));
  for (const extra of outside.entries()) {
    if (!rows.has(extra.key)) {
      rows.set(extra.key, {
        key: extra.key,
        path: extra.path,
        line: pinned.get(extra.key)?.lineId ?? null,
        rate: { down: 0, up: 0 },
        lineDown: {},
        sortScore: 0,
        connections: {},
      });
    }
  }
  return [...rows.values()].map((row) => {
    const extra = outside.get(row.key);
    if (!extra) return { ...row, outside: null };
    const extraDown = total(extra.lines, 'down');
    const extraUp = total(extra.lines, 'up');
    const lineDown = { ...row.lineDown };
    for (const [lineId, rate] of Object.entries(extra.lines)) lineDown[lineId] = (lineDown[lineId] ?? 0) + rate.down;
    const byLine = {};
    for (const item of extra.ids) byLine[item.line] = (byLine[item.line] ?? 0) + 1;
    return {
      ...row,
      // An outside connection may be the first sighting of an updated app;
      // prefer its live path over a saved pin or an idle routed row.
      path: Object.values(row.connections).some((count) => count > 0) ? row.path : extra.path,
      rate: { down: row.rate.down + extraDown, up: row.rate.up + extraUp },
      lineDown,
      sortScore: row.sortScore + extra.sortScore,
      outside: {
        connections: extra.connections,
        byLine,
        beforeRouting: extra.beforeRouting,
        measured: extra.measured,
        rate: { down: extraDown, up: extraUp },
      },
    };
  });
}

function smooth(previous, next, weight) {
  const value = previous * (1 - weight) + next * weight;
  return value < 1 ? 0 : value;
}
