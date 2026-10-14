// Turns the engine's connection list into per-app speeds.
// Pure logic: no I/O, so it can be tested with plain objects.

export const UNKNOWN_APP = 'unknown';
export const SECOND_OUTBOUND = 'second';
export const MAIN_OUTBOUND = 'cable';
// Apps moved to the second connection go through this selector (engine.mjs), so
// Net Switch can point them at the cable while the second connection is down.
export const SECOND_LANE_SELECTOR = 'second-lane';
// Everything else goes through this one, so it can use the second connection
// while the cable is down.
export const MAIN_LANE_SELECTOR = 'main-lane';

const IDLE_KEEP_MS = 10 * 60_000;
const DISPLAY_SMOOTHING = 0.6;
const SORT_SMOOTHING = 0.25;
const LANES = ['main', 'second'];

export function appKey(processPath) {
  return processPath ? processPath.toLowerCase() : UNKNOWN_APP;
}

// chains[0] is the outbound that actually carries the connection, even when it
// went through a lane selector.
export function connectionLane(connection) {
  return connection.chains?.[0] === SECOND_OUTBOUND ? 'second' : 'main';
}

// A connection that went through a lane's selector while it pointed at the
// other line, because its own line was down: by default, one of the second
// connection's apps that went to the cable. The selector never moves a
// connection that is already open, so it stays there until it is closed.
export function isFallbackConnection(connection, selector = SECOND_LANE_SELECTOR, away = MAIN_OUTBOUND) {
  const chains = connection?.chains;
  return Array.isArray(chains) && chains.length >= 2 && chains[0] === away && chains[chains.length - 1] === selector;
}

function zeroLanes() {
  return { main: { down: 0, up: 0 }, second: { down: 0, up: 0 } };
}

export class AppTracker {
  constructor({ idleKeepMs = IDLE_KEEP_MS } = {}) {
    this.idleKeepMs = idleKeepMs;
    this.previousBytes = new Map();
    this.apps = new Map();
    this.laneRates = zeroLanes();
    this.lastPollAt = null;
  }

  reset() {
    this.previousBytes.clear();
    for (const app of this.apps.values()) {
      app.lanes = zeroLanes();
      app.sortScore = 0;
      app.connections = { main: 0, second: 0 };
      app.ids = { main: [], second: [] };
    }
    this.laneRates = zeroLanes();
    this.lastPollAt = null;
  }

  ingest(connections, now) {
    const seconds = this.lastPollAt === null ? null : Math.max((now - this.lastPollAt) / 1000, 0.2);
    const nextBytes = new Map();
    const perApp = new Map();
    const laneBytes = zeroLanes();

    for (const connection of connections) {
      const path = connection.metadata?.processPath || '';
      const key = appKey(path);
      const lane = connectionLane(connection);
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
        entry = { path, lanes: zeroLanes(), connections: { main: 0, second: 0 }, ids: { main: [], second: [] } };
        perApp.set(key, entry);
      }
      entry.lanes[lane].down += down;
      entry.lanes[lane].up += up;
      entry.connections[lane] += 1;
      entry.ids[lane].push(connection.id);
      laneBytes[lane].down += down;
      laneBytes[lane].up += up;
    }

    for (const [key, entry] of perApp) {
      if (!this.apps.has(key)) {
        this.apps.set(key, {
          key,
          path: entry.path,
          lanes: zeroLanes(),
          sortScore: 0,
          lastSeen: now,
          connections: { main: 0, second: 0 },
        });
      }
    }

    for (const app of this.apps.values()) {
      const entry = perApp.get(app.key);
      let total = 0;
      for (const lane of LANES) {
        const down = seconds && entry ? entry.lanes[lane].down / seconds : 0;
        const up = seconds && entry ? entry.lanes[lane].up / seconds : 0;
        app.lanes[lane] = {
          down: smooth(app.lanes[lane].down, down, DISPLAY_SMOOTHING),
          up: smooth(app.lanes[lane].up, up, DISPLAY_SMOOTHING),
        };
        total += down + up;
      }
      app.sortScore = smooth(app.sortScore, total, SORT_SMOOTHING);
      app.connections = entry ? entry.connections : { main: 0, second: 0 };
      app.ids = entry ? entry.ids : { main: [], second: [] };
      if (entry) app.lastSeen = now;
    }

    for (const [key, app] of this.apps) {
      const idle = app.connections.main + app.connections.second === 0;
      if (idle && now - app.lastSeen > this.idleKeepMs) this.apps.delete(key);
    }

    for (const lane of LANES) {
      this.laneRates[lane] = {
        down: seconds ? laneBytes[lane].down / seconds : 0,
        up: seconds ? laneBytes[lane].up / seconds : 0,
      };
    }

    this.previousBytes = nextBytes;
    this.lastPollAt = now;
  }

  // Apps to show: active ones, recently active ones, and every app the person
  // moved to the second connection (even if it is not running right now).
  snapshot(secondAppPaths) {
    const assigned = new Map(secondAppPaths.map((path) => [appKey(path), path]));
    const rows = [...this.apps.values()];
    for (const [key, path] of assigned) {
      if (!this.apps.has(key)) {
        rows.push({ key, path, lanes: zeroLanes(), sortScore: 0, connections: { main: 0, second: 0 } });
      }
    }
    return rows.map((app) => ({
      key: app.key,
      path: app.path,
      lane: assigned.has(app.key) ? 'second' : 'main',
      rate: {
        down: app.lanes.main.down + app.lanes.second.down,
        up: app.lanes.main.up + app.lanes.second.up,
      },
      laneDown: { main: app.lanes.main.down, second: app.lanes.second.down },
      sortScore: app.sortScore,
      connections: { ...app.connections },
    }));
  }

  // Engine connection ids of one app on one lane, from the latest poll.
  connectionIdsFor(key, lane) {
    return [...(this.apps.get(key)?.ids?.[lane] ?? [])];
  }
}

// Connections that go around the routing engine (for example a download that
// was already running when routing started), measured from Windows'
// per-connection byte counts. Same smoothing as routed traffic.
export class OutsideTracker {
  constructor() {
    this.previousBytes = new Map();
    this.apps = new Map();
    this.lastAt = null;
  }

  reset() {
    this.previousBytes.clear();
    this.apps.clear();
    this.lastAt = null;
  }

  // samples: [{ id, path, lane, down, up, beforeRouting }]; down/up are byte
  // totals, or null when Windows could not measure that connection.
  ingest(samples, now) {
    const seconds = this.lastAt === null ? null : Math.max((now - this.lastAt) / 1000, 0.2);
    const nextBytes = new Map();
    const perApp = new Map();
    for (const sample of samples) {
      const key = appKey(sample.path);
      let entry = perApp.get(key);
      if (!entry) {
        entry = { path: sample.path ?? '', lanes: zeroLanes(), connections: 0, beforeRouting: true, measured: false, ids: [] };
        perApp.set(key, entry);
      }
      entry.connections += 1;
      entry.ids.push({ id: sample.id, lane: sample.lane });
      entry.beforeRouting = entry.beforeRouting && sample.beforeRouting;
      if (sample.down === null || sample.down === undefined) continue;
      entry.measured = true;
      const previous = this.previousBytes.get(sample.id);
      if (previous) {
        entry.lanes[sample.lane].down += Math.max(0, sample.down - previous.down);
        entry.lanes[sample.lane].up += Math.max(0, sample.up - previous.up);
      }
      nextBytes.set(sample.id, { down: sample.down, up: sample.up });
    }

    const apps = new Map();
    for (const [key, entry] of perApp) {
      const before = this.apps.get(key);
      const lanes = zeroLanes();
      let total = 0;
      for (const lane of LANES) {
        const down = seconds ? entry.lanes[lane].down / seconds : 0;
        const up = seconds ? entry.lanes[lane].up / seconds : 0;
        lanes[lane] = {
          down: smooth(before?.lanes[lane].down ?? 0, down, DISPLAY_SMOOTHING),
          up: smooth(before?.lanes[lane].up ?? 0, up, DISPLAY_SMOOTHING),
        };
        total += down + up;
      }
      apps.set(key, {
        key,
        path: entry.path,
        lanes,
        connections: entry.connections,
        beforeRouting: entry.beforeRouting,
        measured: entry.measured,
        ids: entry.ids,
        sortScore: smooth(before?.sortScore ?? 0, total, SORT_SMOOTHING),
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

  // Outside connection ids of one app that are not on the given lane.
  idsOffLane(key, lane) {
    return (this.apps.get(key)?.ids ?? []).filter((item) => item.lane !== lane).map((item) => item.id);
  }

  // Every outside connection id of one app, on either line.
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
export function mergeRows(routedRows, outside, secondAppPaths) {
  const assigned = new Set(secondAppPaths.map(appKey));
  const rows = new Map(routedRows.map((row) => [row.key, row]));
  for (const extra of outside.entries()) {
    if (!rows.has(extra.key)) {
      rows.set(extra.key, {
        key: extra.key,
        path: extra.path,
        lane: assigned.has(extra.key) ? 'second' : 'main',
        rate: { down: 0, up: 0 },
        laneDown: { main: 0, second: 0 },
        sortScore: 0,
        connections: { main: 0, second: 0 },
      });
    }
  }
  return [...rows.values()].map((row) => {
    const extra = outside.get(row.key);
    if (!extra) return { ...row, outside: null };
    const extraDown = extra.lanes.main.down + extra.lanes.second.down;
    const extraUp = extra.lanes.main.up + extra.lanes.second.up;
    return {
      ...row,
      rate: { down: row.rate.down + extraDown, up: row.rate.up + extraUp },
      laneDown: {
        main: row.laneDown.main + extra.lanes.main.down,
        second: row.laneDown.second + extra.lanes.second.down,
      },
      sortScore: row.sortScore + extra.sortScore,
      outside: {
        connections: extra.connections,
        byLane: {
          main: extra.ids.filter((item) => item.lane === 'main').length,
          second: extra.ids.filter((item) => item.lane === 'second').length,
        },
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
