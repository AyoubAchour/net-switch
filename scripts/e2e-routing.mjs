// Checks that routing really sends new connections where the rules say, with
// the real engine: the main line by default, an app's own line once it is
// pinned there, and every line while combining. Runs the server in test mode
// (a local proxy instead of the network adapter, so no administrator rights
// and nothing else on the PC changes), with both lines on the same adapter:
// lines are told apart by the engine's outbound, not by the adapter.
//
//   node scripts/e2e-routing.mjs [--engine-dir path\to\engine]
//
// The engine must be in engine\ (scripts\fetch-engine.ps1 puts it there) or
// in the folder --engine-dir names. This script's own connections go through
// the proxy, so this script is the app being routed.
import { spawn } from 'node:child_process';
import { realpathSync } from 'node:fs';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { request } from 'node:http';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import { connect as tlsConnect } from 'node:tls';
import { fileURLToPath } from 'node:url';
import { killTree } from '../lib/ps.mjs';
import { launchOptions, recordLaunch, serverCommand, verifyEngineProcess } from '../tests/windows/launch.mjs';

const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), '..');
// Windows names a program by its real path; Node may run through a link (nvm).
const SELF = realpathSync.native(process.execPath);
const TARGET = { host: '1.1.1.1', port: 443, path: '/cdn-cgi/trace' };
const options = launchOptions();
await recordLaunch(options);

const dataDir = await mkdtemp(path.join(tmpdir(), 'net-switch-e2e-'));
const [serverExe, serverArgs] = serverCommand(options, dataDir, { proxy: true });
const server = spawn(
  serverExe,
  serverArgs,
  { cwd: ROOT, stdio: ['ignore', 'pipe', 'pipe'], windowsHide: true },
);
let serverOutput = '';
server.stdout.on('data', (chunk) => (serverOutput += chunk));
server.stderr.on('data', (chunk) => (serverOutput += chunk));

let session = null;
const open = [];

async function api(route, body) {
  const response = await fetch(`http://127.0.0.1:${session.port}/api/${route}`, {
    method: body === undefined ? 'GET' : 'POST',
    headers: { 'X-Token': session.token, ...(body === undefined ? {} : { 'Content-Type': 'application/json' }) },
    body: body === undefined ? undefined : JSON.stringify(body),
    signal: AbortSignal.timeout(60_000),
  });
  const answer = await response.json();
  if (!response.ok) throw new Error(`${route}: ${answer.error ?? response.status}`);
  return answer;
}

async function until(what, check, seconds = 60) {
  const deadline = Date.now() + seconds * 1000;
  let last;
  while (Date.now() < deadline) {
    try {
      last = await check();
      if (last) return last;
    } catch (error) {
      last = error.message;
    }
    await delay(250);
  }
  throw new Error(`${what} did not happen within ${seconds} s${last ? ` (last: ${JSON.stringify(last)})` : ''}`);
}

// Starting checks the engine's files against their checksums first, which
// takes a while on a busy PC.
async function routingOn() {
  let routing = null;
  try {
    return await until('routing turning on', async () => {
      const state = await api('state');
      routing = state.routing;
      if (state.routing.status === 'on') return state;
      if (state.routing.status === 'error' && /missing|doesn’t match/.test(state.routing.error ?? '')) {
        throw new Error(`the engine can't start: ${state.routing.error}`);
      }
      return null;
    }, 120);
  } catch (error) {
    throw new Error(`${error.message}; routing was ${JSON.stringify(routing)}`);
  }
}

// One HTTPS request through the test-mode proxy, left open so the server's
// next poll sees it. Resolves once the answer has arrived.
// One deadline covers the proxy, TLS and the answer; any other answer, or the
// connection closing first, fails the request instead of hanging the test.
const REQUEST_TIMEOUT_MS = 20_000;
function connectThroughProxy(proxyPort) {
  return new Promise((resolve, reject) => {
    let settled = false;
    const sockets = [];
    const fail = (error) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      for (const socket of sockets) socket.destroy();
      reject(error);
    };
    const timer = setTimeout(() => fail(new Error('the request through the proxy took too long')), REQUEST_TIMEOUT_MS);
    const tunnel = request({ host: '127.0.0.1', port: proxyPort, method: 'CONNECT', path: `${TARGET.host}:${TARGET.port}` });
    tunnel.on('error', fail);
    tunnel.on('connect', (response, socket) => {
      sockets.push(socket);
      if (response.statusCode !== 200) {
        fail(new Error(`the proxy answered ${response.statusCode}`));
        return;
      }
      const secure = tlsConnect({ socket, servername: 'one.one.one.one' }, () => {
        secure.write(`GET ${TARGET.path} HTTP/1.1\r\nHost: one.one.one.one\r\nConnection: keep-alive\r\n\r\n`);
      });
      sockets.push(secure);
      let text = '';
      secure.on('data', (chunk) => {
        if (settled) return;
        text += chunk;
        if (!text.includes('\r\n\r\n')) return;
        const status = /^HTTP\/1\.[01] (\d{3})/.exec(text)?.[1];
        if (status !== '200') {
          fail(new Error(`the site answered ${status ?? 'something unreadable'}`));
          return;
        }
        settled = true;
        clearTimeout(timer);
        open.push(secure);
        resolve(secure);
      });
      secure.on('end', () => fail(new Error('the site closed the connection before answering')));
      secure.on('error', fail);
    });
    tunnel.end();
  });
}

// Closes this script's connections and waits until the server no longer
// counts any, so the next check only sees new ones.
async function closeAll() {
  for (const socket of open.splice(0)) socket.destroy();
  if (!session || server.exitCode !== null) return;
  const self = SELF.toLowerCase();
  await until('closed connections leaving the count', async () => {
    const state = await api('state');
    const row = state.apps.find((app) => app.path.toLowerCase() === self);
    return Object.values(row?.connections ?? {}).every((count) => count === 0);
  }, 20);
}

// This script's connections per line, as the server counts them after a poll.
async function connectionsPerLine(expected) {
  const self = SELF.toLowerCase();
  let apps = [];
  try {
    return await until(`${expected} connections showing in the window`, async () => {
      const state = await api('state');
      apps = state.apps.map((app) => ({ path: app.path, connections: app.connections }));
      const row = state.apps.find((app) => app.path.toLowerCase() === self);
      const counts = row?.connections ?? {};
      return Object.values(counts).reduce((sum, count) => sum + count, 0) >= expected ? counts : null;
    }, 20);
  } catch (error) {
    throw new Error(`${error.message}; the window shows ${JSON.stringify(apps)}`);
  }
}

async function openMany(count, proxyPort) {
  // One after another, as an app opening connections would: Windows hands
  // out the proxy's client ports in order, which is what combining splits.
  for (let i = 0; i < count; i += 1) await connectThroughProxy(proxyPort);
}

function check(condition, message) {
  if (!condition) throw new Error(message);
  console.log(`ok - ${message}`);
}

let failed = false;
try {
  session = await until('the server starting', async () => JSON.parse(await readFile(path.join(dataDir, 'server.json'), 'utf8')), 60);
  let state = await routingOn();
  await verifyEngineProcess(options, dataDir);
  check(state.lines.length === 1, `the first line is the adapter Windows uses (${state.lines[0]?.alias})`);
  const main = state.lines[0];

  // A second line on the same adapter, so this works on a PC with one.
  await api('lines/add', { alias: main.alias });
  state = await routingOn();
  check(state.lines.length === 2, 'a second line was added and routing restarted');
  const second = state.lines[1];
  const proxyPort = state.routing.proxyPort;

  await openMany(3, proxyPort);
  let counts = await connectionsPerLine(3);
  check(counts[main.id] === 3 && !counts[second.id], `without a choice, connections use the main line (${JSON.stringify(counts)})`);
  await closeAll();

  await api('app-line', { path: SELF, line: second.id });
  await openMany(3, proxyPort);
  counts = await until('the pinned connections showing', async () => {
    const now = await connectionsPerLine(3);
    return now[second.id] === 3 ? now : null;
  }, 20);
  check(counts[second.id] === 3 && !counts[main.id], `a pinned app's new connections use its line (${JSON.stringify(counts)})`);
  await closeAll();

  // Pinned to the main line: kept there even while combining.
  await api('app-line', { path: SELF, line: null });
  await api('combine', { on: true, mode: 'manual', weights: { [main.id]: 1, [second.id]: 1 } });
  state = await api('state');
  check(state.lines.every((line) => line.share === 0.5), 'combining by hand gives each line half');
  await openMany(12, proxyPort);
  counts = await connectionsPerLine(12);
  check(counts[main.id] >= 3 && counts[second.id] >= 3, `while combining, new connections use both lines (${JSON.stringify(counts)})`);
  await closeAll();

  await api('app-line', { path: SELF, line: main.id });
  await openMany(6, proxyPort);
  counts = await until('the kept connections showing', async () => {
    const now = await connectionsPerLine(6);
    return now[main.id] === 6 ? now : null;
  }, 20);
  check(counts[main.id] === 6, `an app pinned to the main line stays on it while combining (${JSON.stringify(counts)})`);
  await closeAll();

  await api('quit', {});
  await until('the server ending', async () => server.exitCode !== null, 30);
  check(server.exitCode === 0, 'quitting stops routing and ends the server');
  console.log('routing end-to-end test passed');
} catch (error) {
  failed = true;
  console.error(`not ok - ${error.message}`);
  console.error('--- server output ---');
  console.error(serverOutput);
  const log = await readFile(path.join(dataDir, 'server.log'), 'utf8').catch(() => '');
  console.error('--- server.log ---');
  console.error(log.split('\n').slice(-40).join('\n'));
} finally {
  for (const socket of open.splice(0)) socket.destroy();
  // Quit the normal way, so the engine stops too; else end the whole tree.
  if (server.exitCode === null && session) await api('quit', {}).catch(() => {});
  await delay(1000);
  if (server.exitCode === null) await killTree(server.pid);
  await rm(dataDir, { recursive: true, force: true }).catch(() => {});
}
process.exit(failed ? 1 : 0);
