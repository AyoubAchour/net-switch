// Serves the Net Switch window with made-up traffic, for working on the UI
// and taking screenshots without administrator rights, a second connection or
// the routing engine. Nothing here touches the network setup.
//
//   node dev/demo-server.mjs        then open http://127.0.0.1:47841/#token=demo
//
// The apps and speeds are invented; lane switches and the combine toggle work.
import { readFile } from 'node:fs/promises';
import { createServer } from 'node:http';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const PORT = 47841;
const UI_DIR = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'ui');
const FILES = {
  '/': ['index.html', 'text/html; charset=utf-8'],
  '/app.js': ['app.js', 'text/javascript; charset=utf-8'],
  '/styles.css': ['styles.css', 'text/css; charset=utf-8'],
  '/favicon.svg': ['favicon.svg', 'image/svg+xml'],
};
const KB = 1024;

// Each app: name, download in KB/s around which it wanders, and its lane.
const apps = [
  { name: 'Steam', kb: 2600, lane: 'main' },
  { name: 'Firefox', kb: 640, lane: 'second' },
  // Kept on the cable: calls stay on one line even while combining.
  { name: 'Discord', kb: 14, lane: 'main', cableOnly: true },
  { name: 'Spotify', kb: 160, lane: 'second' },
  { name: 'OneDrive', kb: 40, lane: 'main' },
  { name: 'Visual Studio Code', kb: 3, lane: 'main' },
  // Windows services share one program, so they can switch lines but not reconnect.
  { name: 'Windows services', kb: 1, lane: 'main', service: true },
];
let combine = true;
// node dev/demo-server.mjs --update also shows a newer release on offer.
let offerUpdate = process.argv.includes('--update');
let updateChecks = true;
const DEMO_UPDATE = {
  version: '9.9.9',
  page: 'https://github.com/AyoubAchour/net-switch/releases/latest',
  installer: 'https://github.com/AyoubAchour/net-switch/releases/latest',
};

// A steady wobble, so the meters move like real traffic.
function wobble(base, seed) {
  const t = Date.now() / 1000;
  return Math.max(0, base * (1 + 0.18 * Math.sin(t * 0.9 + seed) + 0.08 * Math.sin(t * 2.3 + seed * 2)));
}

function state() {
  const rows = apps.map((app, index) => {
    const down = wobble(app.kb * KB, index);
    // While combining, an app on the cable spreads over both lines, unless it
    // is kept on the cable.
    const share = app.lane === 'second' ? 1 : combine && !app.cableOnly ? 0.45 : 0;
    return {
      key: app.name.toLowerCase(),
      path: `C:\\Program Files\\${app.name}\\${app.name}.exe`,
      name: app.name,
      hasIcon: false,
      switchable: true,
      reconnectable: !app.service,
      lane: app.lane,
      cableOnly: Boolean(app.cableOnly),
      rate: { down, up: down * 0.03 },
      laneDown: { main: down * (1 - share), second: down * share },
      sortScore: down,
      connections: { main: app.lane === 'second' ? 0 : 3, second: share > 0 ? 3 : 0 },
      outside: null,
    };
  });
  const sum = (lane) => rows.reduce((total, row) => total + row.laneDown[lane], 0);
  return {
    mode: 'tun',
    elevated: true,
    version: '0.2.0',
    update: offerUpdate && updateChecks ? DEMO_UPDATE : null,
    updateChecks,
    features: { reconnect: true, combine: true, cableOnly: true },
    combine: { on: combine, active: combine },
    routing: { status: 'on', wanted: true, error: null, measuring: true, proxyPort: null, retryAt: null },
    lanes: {
      main: {
        alias: 'Ethernet', label: 'Cable', connected: true, problem: null, ping: 18, connections: 23,
        carryingApps: true, rate: { down: sum('main'), up: sum('main') * 0.04 }, movedBack: null,
      },
      second: {
        alias: 'Wi-Fi', label: 'Wi-Fi stick', kind: 'wifi', connected: true, problem: null, ping: 31, connections: 14,
        ssid: 'HomeNet', carryingApps: true, rate: { down: sum('second'), up: sum('second') * 0.04 }, movedBack: null,
      },
    },
    candidates: [],
    apps: rows,
    setup: { cableNotDefault: false, wifiBlocked: false, keepBothConnected: false, changed: { cableDefault: false, keepBoth: false } },
  };
}

async function body(request) {
  const chunks = [];
  for await (const chunk of request) chunks.push(chunk);
  return chunks.length ? JSON.parse(Buffer.concat(chunks).toString('utf8')) : {};
}

const actions = {
  'GET /api/state': async () => state(),
  'POST /api/app-lane': async ({ path: appPath, lane }) => {
    const app = apps.find((item) => appPath?.includes(`\\${item.name}.exe`));
    if (app) {
      app.lane = lane === 'second' ? 'second' : 'main';
      app.cableOnly = lane === 'cable';
    }
    return state();
  },
  'POST /api/combine': async ({ on }) => {
    combine = Boolean(on);
    return state();
  },
  'POST /api/update/dismiss': async () => {
    offerUpdate = false;
    return state();
  },
  'POST /api/update/checks': async ({ on }) => {
    updateChecks = Boolean(on);
    return state();
  },
};

createServer(async (request, response) => {
  const url = new URL(request.url, `http://127.0.0.1:${PORT}`);
  const action = actions[`${request.method} ${url.pathname}`];
  if (action) {
    const result = await action(request.method === 'POST' ? await body(request) : {});
    response.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8' });
    response.end(JSON.stringify(result));
    return;
  }
  const file = FILES[url.pathname];
  if (!file) {
    response.writeHead(404).end();
    return;
  }
  response.writeHead(200, { 'Content-Type': file[1] });
  response.end(await readFile(path.join(UI_DIR, file[0])));
}).listen(PORT, '127.0.0.1', () => {
  console.log(`Demo window: http://127.0.0.1:${PORT}/#token=demo`);
});
