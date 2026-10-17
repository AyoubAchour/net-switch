// Serves the Net Switch window with made-up lines and traffic, for working on
// the UI and taking screenshots without administrator rights, extra adapters
// or the routing engine. Nothing here touches the network setup.
//
//   node dev/demo-server.mjs        then open http://127.0.0.1:47841/#token=demo
//
// The lines, apps and speeds are invented, and every control in the window
// changes them. Options, to see other situations:
//
//   --update        also offer a newer release
//   --lines=N       start with 1 to 6 lines (3 by default)
//   --no-apps       no app is using the internet
//   --over-cap      the phone has used up its data cap
//   --down=N        line N (1 is the main line) has no internet
//   --long          very long names
//   --manual        combining with shares set by hand
//   --no-combine    combining off
//   --setup         the notices about Windows settings
//   --port=N        another port
//
// POST /api/demo with the same options as JSON ({ "lines": 5, "overCap": true,
// "update": true }) starts over without restarting the server.
// POST /api/demo/line { "index": 2, "down": true } takes a line down or brings
// it back without starting over (1 is the main line), with its event for the tray.
import { readFile } from 'node:fs/promises';
import { createServer } from 'node:http';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const UI_DIR = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'ui');
const FILES = {
  '/': ['index.html', 'text/html; charset=utf-8'],
  '/app.js': ['app.js', 'text/javascript; charset=utf-8'],
  '/styles.css': ['styles.css', 'text/css; charset=utf-8'],
  '/favicon.svg': ['favicon.svg', 'image/svg+xml'],
};
const KB = 1024;
const MB = 1024 * KB;
const GB = 1024 * MB;

// The adapters this made-up PC has, in the order they become lines. speed is
// the download in MB/s each one manages, which Auto shares follow.
const ADAPTERS = [
  { alias: 'Ethernet', label: 'Cable', kind: 'wired', ssid: null, ping: 18, speed: 1.6 },
  { alias: 'Wi-Fi', label: 'Wi-Fi stick', kind: 'wifi', ssid: 'HomeNet', ping: 31, speed: 2.4 },
  {
    alias: 'Ethernet 3', label: 'Phone', kind: 'phone', ssid: null, ping: 54, speed: 0.8,
    metered: true, cap: { bytes: 10 * GB, period: 'month' }, used: 6.2 * GB,
  },
  { alias: 'Wi-Fi 2', label: 'Wi-Fi stick 2', kind: 'wifi', ssid: 'Upstairs', ping: 27, speed: 1.9 },
  { alias: 'Ethernet 2', label: 'Ethernet 2', kind: 'wired', ssid: null, ping: 12, speed: 3.1 },
  { alias: 'Cellular', label: '4G modem', kind: 'other', ssid: null, ping: 63, speed: 1.1, metered: true },
];
const LONG_LABELS = [
  'Fibre from the basement router',
  'Wi-Fi stick on the upstairs network',
  'Ayoub’s phone on the unlimited weekend plan',
  'Second Wi-Fi stick in the back of the PC',
  'USB network adapter from the office drawer',
  'Mobile broadband modem by the window',
];

// Each app: name, download in KB/s around which it wanders, and the line it is
// put on, by position (null: the default).
const APPS = [
  { name: 'Steam', kb: 2600, line: null },
  // On the second line, with two older connections still on the main one.
  { name: 'Firefox', kb: 640, line: 1, stray: 2 },
  // Kept on the main line: calls stay on one line even while combining.
  { name: 'Discord', kb: 14, line: 0 },
  { name: 'Spotify', kb: 160, line: 2 },
  { name: 'OneDrive', kb: 40, line: null },
  { name: 'Visual Studio Code', kb: 3, line: null },
  // Windows services share one program, so they can switch lines but not reconnect.
  { name: 'Windows services', kb: 1, line: null, service: true },
];

// The Start menu's apps, for Add an app. Some aren't running.
const INSTALLED = ['Discord', 'Epic Games Launcher', 'Firefox', 'OBS Studio', 'Slack', 'Spotify', 'Steam', 'Visual Studio Code', 'Zoom'].map(
  (name) => ({ name, path: `C:\\Program Files\\${name}\\${name}.exe`, hasIcon: false }),
);

const DEMO_UPDATE = {
  version: '9.9.9',
  page: 'https://github.com/AyoubAchour/net-switch/releases/latest',
  installer: 'https://github.com/AyoubAchour/net-switch/releases/latest',
};

const startOptions = parseArgs(process.argv.slice(2));
const PORT = startOptions.port ?? 47841;
let offerUpdate = Boolean(startOptions.update);

let lines = [];
let candidates = [];
let apps = [];
let combine = { on: true, mode: 'auto' };
let routingOn = true;
let settings = {};
let setup = {};
let events = [];
let lastTick = Date.now();

function parseArgs(args) {
  const options = {};
  for (const arg of args) {
    const [name, value] = arg.replace(/^--/, '').split('=');
    if (name === 'lines') options.lines = Number(value);
    else if (name === 'down') options.down = Number(value);
    else if (name === 'port') options.port = Number(value);
    else if (name === 'no-apps') options.apps = false;
    else if (name === 'over-cap') options.overCap = true;
    else if (name === 'no-combine') options.combine = false;
    else if (name === 'manual') options.manual = true;
    else if (name === 'long') options.long = true;
    else if (name === 'setup') options.setup = true;
    else if (name === 'update') options.update = true;
  }
  return options;
}

function newId() {
  return Math.random().toString(36).slice(2, 6);
}

function makeLine(adapter, label) {
  return {
    id: newId(),
    alias: adapter.alias,
    label: label ?? adapter.label,
    kind: adapter.kind,
    ssid: adapter.ssid,
    ping: adapter.ping,
    speed: adapter.speed,
    metered: Boolean(adapter.metered),
    strict: false,
    cap: adapter.cap ? { ...adapter.cap } : null,
    used: adapter.used ?? 0.4 * GB,
    weight: 1,
    down: false,
  };
}

function asCandidate(adapter) {
  return { alias: adapter.alias, label: adapter.label, kind: adapter.kind, ssid: adapter.ssid ?? null };
}

function reset(options = {}) {
  const count = Math.min(Math.max(Math.round(options.lines ?? 3), 1), ADAPTERS.length);
  lines = ADAPTERS.slice(0, count).map((adapter, index) => makeLine(adapter, options.long ? LONG_LABELS[index] : null));
  candidates = ADAPTERS.slice(count, count + 1).map(asCandidate);
  const phone = lines.find((line) => line.kind === 'phone');
  if (options.overCap && phone) phone.used = 10.3 * GB;
  if (options.down && lines[options.down - 1]) lines[options.down - 1].down = true;
  combine = { on: options.combine !== false && count > 1, mode: options.manual ? 'manual' : 'auto' };
  if (options.manual && count > 1) lines.forEach((line, index) => (line.weight = index === 0 ? 50 : 50 / (count - 1)));
  apps =
    options.apps === false
      ? []
      : APPS.map((app, index) => ({
          ...app,
          name: options.long && index === 1 ? 'Microsoft Edge WebView2 helper for the company sign-in page' : app.name,
          line: app.line === null ? null : (lines[app.line]?.id ?? null),
          stray: app.stray && lines[app.line] && app.line !== 0 ? { lineId: lines[0].id, count: app.stray } : null,
        }));
  routingOn = true;
  if (options.update !== undefined) offerUpdate = Boolean(options.update);
  settings = { autostart: false, checkForUpdates: true, probeTargets: ['1.1.1.1:443', '8.8.8.8:443'] };
  setup = {
    cableNotDefault: Boolean(options.setup),
    wifiBlocked: false,
    keepBothConnected: Boolean(options.setup),
    changed: { cableDefault: false, keepBoth: Boolean(options.setup) },
  };
  events = [];
  if (lines[1]) {
    const at = Date.now() - 3 * 60 * 60 * 1000;
    addEvent('down', lines[1], `The ${lines[1].label} is down. Its apps use the ${lines[0].label}.`, at);
    addEvent('up', lines[1], `The ${lines[1].label} is back.`, at + 4 * 60 * 1000);
  }
  if (phone && exhausted(phone)) addEvent('exhausted', phone, `The ${phone.label} has used its data cap.`);
  lastTick = Date.now();
}

function addEvent(kind, line, text, at = Date.now()) {
  events.push({ id: newId(), at, kind, lineId: line.id, text });
  events = events.slice(-20);
}

// A steady wobble, so the meters move like real traffic.
function wobble(base, seed) {
  const t = Date.now() / 1000;
  return Math.max(0, base * (1 + 0.18 * Math.sin(t * 0.9 + seed) + 0.08 * Math.sin(t * 2.3 + seed * 2)));
}

// Splits total into 5% steps that add up to it, in proportion to weights.
function steps(weights, total = 100) {
  const units = total / 5;
  const sum = weights.reduce((a, b) => a + b, 0);
  const exact = weights.map((weight) => (sum > 0 ? (weight / sum) * units : units / weights.length));
  const counts = exact.map(Math.floor);
  let left = units - counts.reduce((a, b) => a + b, 0);
  const order = exact.map((value, index) => [value - Math.floor(value), index]).sort((a, b) => b[0] - a[0]);
  for (const [, index] of order) {
    if (left <= 0) break;
    counts[index] += 1;
    left -= 1;
  }
  return counts.map((count) => count * 5);
}

function periodStart(period) {
  const now = new Date();
  return period === 'day'
    ? new Date(now.getFullYear(), now.getMonth(), now.getDate()).toISOString()
    : new Date(now.getFullYear(), now.getMonth(), 1).toISOString();
}

function exhausted(line) {
  return Boolean(line.cap) && line.used >= line.cap.bytes;
}

function available(line) {
  return !line.down && !exhausted(line);
}

// Where a line's own apps go now: itself, or the first other line in priority
// order that works and isn't kept for chosen apps.
function targetOf(line) {
  if (available(line)) return line.id;
  const other = lines.find((item) => item !== line && available(item) && !item.strict);
  return other ? other.id : line.id;
}

function sharers() {
  return lines.filter((line) => !line.strict && !exhausted(line));
}

function combineActive() {
  return combine.on && routingOn && sharers().filter((line) => !line.down).length >= 2;
}

// Each sharing line's part of new connections, 0 to 1, while combining.
function shares() {
  if (!combineActive()) return {};
  const live = sharers().filter((line) => !line.down);
  const percents = steps(live.map((line) => (combine.mode === 'manual' ? line.weight : line.speed)));
  return Object.fromEntries(live.map((line, index) => [line.id, percents[index] / 100]));
}

function state() {
  const now = Date.now();
  const seconds = Math.min(5, (now - lastTick) / 1000);
  lastTick = now;
  const split = shares();
  const main = lines[0];

  const rows = apps.map((app, index) => {
    const down = routingOn ? wobble(app.kb * KB, index) : 0;
    const pinned = lines.find((line) => line.id === app.line);
    let parts;
    if (pinned) parts = { [targetOf(pinned)]: 1 };
    else if (combineActive()) parts = split;
    else parts = { [targetOf(main)]: 1 };
    const lineDown = {};
    const connections = {};
    for (const line of lines) {
      const part = parts[line.id] ?? 0;
      lineDown[line.id] = down * part;
      connections[line.id] = part > 0 ? Math.max(1, Math.round(4 * part)) : 0;
    }
    if (app.stray && app.stray.until && app.stray.until < now) app.stray = null;
    if (app.stray && connections[app.stray.lineId] !== undefined) connections[app.stray.lineId] += app.stray.count;
    return {
      key: app.name.toLowerCase(),
      path: `C:\\Program Files\\${app.name}\\${app.name}.exe`,
      name: app.name,
      hasIcon: false,
      switchable: true,
      reconnectable: !app.service,
      line: app.line,
      rate: { down, up: down * 0.03 },
      lineDown,
      sortScore: down,
      connections,
      outside: null,
    };
  });

  const lineRows = lines.map((line, index) => {
    const target = targetOf(line);
    const down = routingOn ? rows.reduce((total, row) => total + row.lineDown[line.id], 0) + (line.down ? 0 : 18 * KB) : 0;
    const up = down * 0.04;
    line.used += (down + up) * seconds;
    if (line.cap && line.used >= line.cap.bytes && !line.wasExhausted) {
      addEvent('exhausted', line, `The ${line.label} has used its data cap.`);
    }
    line.wasExhausted = exhausted(line);
    return {
      id: line.id,
      alias: line.alias,
      label: line.label,
      kind: line.kind,
      main: index === 0,
      connected: true,
      problem: line.down ? 'no internet' : null,
      ping: routingOn && !line.down ? line.ping : null,
      connections: routingOn ? rows.reduce((total, row) => total + row.connections[line.id], 0) + (line.down ? 0 : 4) : null,
      carrying: routingOn && target === line.id,
      target: routingOn ? target : null,
      rate: { down, up },
      ssid: line.ssid,
      metered: line.metered,
      strict: line.strict,
      cap: line.cap,
      usage: { bytes: Math.round(line.used), periodStart: periodStart(line.cap?.period ?? 'month') },
      exhausted: exhausted(line),
      weight: line.weight,
      share: combine.on ? (split[line.id] ?? 0) : null,
    };
  });

  return {
    mode: 'tun',
    elevated: true,
    version: '0.2.0',
    update: offerUpdate && settings.checkForUpdates ? DEMO_UPDATE : null,
    features: { reconnect: true, combine: true, lines: true, installedApps: true },
    combine: { on: combine.on, active: combineActive(), mode: combine.mode },
    routing: { status: routingOn ? 'on' : 'off', wanted: routingOn, error: null, measuring: routingOn, proxyPort: null, retryAt: null },
    lines: lineRows,
    candidates,
    apps: rows,
    events,
    settings,
    setup,
  };
}

function clientError(message) {
  return Object.assign(new Error(message), { status: 400 });
}

function lineFor(id) {
  const line = lines.find((item) => item.id === id);
  if (!line) throw clientError('That line isn’t there any more.');
  return line;
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function body(request) {
  const chunks = [];
  for await (const chunk of request) chunks.push(chunk);
  return chunks.length ? JSON.parse(Buffer.concat(chunks).toString('utf8')) : {};
}

// Changing lines restarts routing in the real server, so those answer slower.
const RESTART_MS = 700;
const QUICK_MS = 150;

const actions = {
  'GET /api/state': async () => state(),
  'POST /api/routing': async ({ on }) => {
    await sleep(RESTART_MS);
    routingOn = Boolean(on);
    return state();
  },
  'GET /api/installed-apps': async () => {
    await sleep(RESTART_MS);
    return INSTALLED;
  },
  'POST /api/app-line': async ({ path: appPath, line }) => {
    await sleep(QUICK_MS);
    let app = apps.find((item) => appPath?.includes(`\\${item.name}.exe`));
    // An app from the Start menu that isn't running yet: listed from now on.
    const fromMenu = INSTALLED.find((item) => item.path === appPath);
    if (!app && fromMenu) {
      app = { name: fromMenu.name, kb: 0, line: null };
      apps.push(app);
    }
    if (!app) throw clientError('That app isn’t using the internet any more.');
    if (line !== null) lineFor(line);
    // Connections that were open stay on the old line for a while, as for real.
    const before = lines.find((item) => item.id === app.line) ?? lines[0];
    if (app.line !== line && before && line !== null) {
      app.stray = { lineId: targetOf(before), count: 2, until: Date.now() + 20_000 };
    }
    app.line = line;
    return state();
  },
  'POST /api/reconnect': async ({ key }) => {
    await sleep(QUICK_MS);
    const app = apps.find((item) => item.name.toLowerCase() === key);
    const closed = app?.stray?.count ?? 0;
    if (app) app.stray = null;
    return { closed, failed: 0, state: state() };
  },
  'POST /api/lines/add': async ({ alias }) => {
    const index = candidates.findIndex((item) => item.alias === alias);
    if (index < 0) throw clientError('That adapter isn’t there any more. Plug it in and try again.');
    await sleep(RESTART_MS);
    const adapter = ADAPTERS.find((item) => item.alias === alias);
    const line = makeLine(adapter);
    lines.push(line);
    candidates.splice(index, 1);
    return state();
  },
  'POST /api/lines/remove': async ({ id }) => {
    const line = lineFor(id);
    if (lines.length === 1) throw clientError('Net Switch needs at least one line.');
    await sleep(RESTART_MS);
    lines = lines.filter((item) => item !== line);
    for (const app of apps) if (app.line === id) app.line = null;
    const adapter = ADAPTERS.find((item) => item.alias === line.alias);
    candidates.push(asCandidate(adapter));
    if (lines.length < 2) combine.on = false;
    return state();
  },
  'POST /api/lines/update': async ({ id, label, metered, strict, cap }) => {
    const line = lineFor(id);
    if (label !== undefined) {
      const name = typeof label === 'string' ? label.trim() : '';
      if (!name) throw clientError('Give the line a name.');
      if (name.length > 40) throw clientError('Keep the name under 40 characters.');
      line.label = name;
    }
    if (metered !== undefined) {
      line.metered = Boolean(metered);
      if (!line.metered) line.strict = false;
    }
    if (strict !== undefined) {
      if (strict && !line.metered) throw clientError('Only a metered line can be kept for the apps you choose.');
      await sleep(RESTART_MS);
      line.strict = Boolean(strict);
    }
    if (cap !== undefined) {
      if (cap !== null && !(cap.bytes > 0 && ['day', 'month'].includes(cap.period))) {
        throw clientError('Enter a data cap above 0 GB, per day or per month.');
      }
      line.cap = cap;
    }
    await sleep(QUICK_MS);
    return state();
  },
  'POST /api/lines/order': async ({ ids }) => {
    const same = Array.isArray(ids) && ids.length === lines.length && lines.every((line) => ids.includes(line.id));
    if (!same) throw clientError('The lines changed meanwhile. Try again.');
    await sleep(RESTART_MS);
    lines = ids.map((id) => lineFor(id));
    return state();
  },
  'POST /api/combine': async ({ on, mode, weights }) => {
    await sleep(QUICK_MS);
    if (on !== undefined) combine.on = Boolean(on) && lines.length > 1;
    if (mode !== undefined) combine.mode = mode === 'manual' ? 'manual' : 'auto';
    if (weights) {
      for (const [id, weight] of Object.entries(weights)) {
        const line = lineFor(id);
        if (!(weight >= 0)) throw clientError('A share can’t be below 0.');
        line.weight = weight;
      }
    }
    return state();
  },
  'POST /api/settings': async ({ autostart, checkForUpdates, probeTargets }) => {
    await sleep(QUICK_MS);
    if (autostart !== undefined) settings.autostart = Boolean(autostart);
    if (checkForUpdates !== undefined) settings.checkForUpdates = Boolean(checkForUpdates);
    if (probeTargets !== undefined) {
      const valid =
        Array.isArray(probeTargets) &&
        probeTargets.length > 0 &&
        probeTargets.every((item) => /^[\w.-]+:\d{1,5}$/.test(item) && Number(item.split(':').pop()) <= 65535);
      if (!valid) throw clientError('Write each test site as address:port, like 1.1.1.1:443.');
      settings.probeTargets = probeTargets;
    }
    return state();
  },
  'POST /api/update/dismiss': async () => {
    offerUpdate = false;
    return state();
  },
  'POST /api/setup/cable-default': async () => {
    await sleep(RESTART_MS);
    setup.cableNotDefault = false;
    setup.changed.cableDefault = true;
    return state();
  },
  'POST /api/setup/keep-both': async () => {
    await sleep(RESTART_MS);
    setup.keepBothConnected = false;
    setup.wifiBlocked = false;
    setup.changed.keepBoth = true;
    return state();
  },
  'POST /api/setup/undo': async () => {
    await sleep(RESTART_MS);
    setup.changed = { cableDefault: false, keepBoth: false };
    return state();
  },
  // The demo keeps running; reload the page to get the window back.
  'POST /api/quit': async () => ({ ok: true }),
  'POST /api/demo': async (options) => {
    reset(options);
    return state();
  },
  'POST /api/demo/line': async ({ index, down }) => {
    const line = lines[Number(index) - 1];
    if (!line) throw clientError('There’s no line with that number.');
    if (line.down !== Boolean(down)) {
      line.down = Boolean(down);
      addEvent(line.down ? 'down' : 'up', line, line.down ? `${line.label} is down: it doesn’t reach the internet.` : `${line.label} is back.`);
    }
    return state();
  },
};

reset(startOptions);

createServer(async (request, response) => {
  const url = new URL(request.url, `http://127.0.0.1:${PORT}`);
  const action = actions[`${request.method} ${url.pathname}`];
  if (action) {
    try {
      const result = await action(request.method === 'POST' ? await body(request) : {});
      response.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8' });
      response.end(JSON.stringify(result));
    } catch (error) {
      response.writeHead(error.status ?? 500, { 'Content-Type': 'application/json; charset=utf-8' });
      response.end(JSON.stringify({ error: error.status ? error.message : 'Something went wrong. Try again.' }));
      if (!error.status) console.error(error);
    }
    return;
  }
  const file = FILES[url.pathname];
  if (!file) {
    response.writeHead(404).end();
    return;
  }
  // The same rules as the real window, so the demo catches what they forbid.
  response.writeHead(200, {
    'Content-Type': file[1],
    'Cache-Control': 'no-cache',
    'Content-Security-Policy':
      "default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; connect-src 'self'; frame-ancestors 'none'",
  });
  response.end(await readFile(path.join(UI_DIR, file[0])));
}).listen(PORT, '127.0.0.1', () => {
  console.log(`Demo window: http://127.0.0.1:${PORT}/#token=demo`);
});
