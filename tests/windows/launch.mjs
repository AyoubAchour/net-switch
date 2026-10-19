import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import { readFile, realpath, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { identity, run, until } from './testisp/harness.mjs';

function argument(name, fallback) {
  const index = process.argv.indexOf(name);
  if (index === -1) return fallback;
  assert(process.argv[index + 1] && !process.argv[index + 1].startsWith('--'), `${name} needs a value`);
  return process.argv[index + 1];
}

export function launchOptions() {
  const server = path.resolve(argument('--server-exe', process.execPath));
  const nodeServer = server.toLowerCase() === process.execPath.toLowerCase();
  const entry = argument('--server-entry', nodeServer ? 'server.mjs' : null);
  const engineDir = argument('--engine-dir', 'engine');
  return {
    server, entry: entry ? path.resolve(entry) : null,
    engine: path.resolve(argument('--engine-exe', path.join(engineDir, 'sing-box.exe'))),
    profile: argument('--profile', 'baseline'),
    serverVersionArgs: JSON.parse(argument('--server-version-args', nodeServer ? '["--version"]' : '["version"]')),
    engineVersionArgs: JSON.parse(argument('--engine-version-args', '["version"]')),
  };
}

export async function recordLaunch(options, file) {
  const binaries = { server: await identity(options.server, options.serverVersionArgs), engine: await identity(options.engine, options.engineVersionArgs) };
  if (options.entry) {
    const packageJSON = JSON.parse(await readFile('package.json', 'utf8'));
    binaries.server.entry = { path: options.entry, version: packageJSON.version,
      sha256: createHash('sha256').update(await readFile(options.entry)).digest('hex') };
  }
  console.log(`Executables under test: ${JSON.stringify(binaries)}`);
  if (file) await writeFile(file, JSON.stringify(binaries, null, 2));
  return binaries;
}

export function serverCommand(options, dataDir, { proxy = false } = {}) {
  return [options.server, [
    ...(options.entry ? [options.entry] : []), ...(proxy ? ['--dev-proxy'] : []),
    '--user-data', dataDir, '--machine-data', dataDir, '--engine-dir', path.dirname(options.engine),
  ]];
}

export async function startServer(options, dataDir, output) {
  const [exe, args] = serverCommand(options, dataDir);
  const child = spawn(exe, args, { windowsHide: true, stdio: ['ignore', 'pipe', 'pipe'] });
  child.stdout.on('data', output); child.stderr.on('data', output);
  let spawnError;
  child.on('error', (error) => { spawnError = error; });
  let session;
  try {
    session = await until(async () => {
      if (spawnError) throw spawnError;
      if (child.exitCode !== null) throw new Error(`Server exited ${child.exitCode}`);
      const candidate = JSON.parse(await readFile(path.join(dataDir, 'server.json'), 'utf8'));
      // A crash may leave a stale session file from the preceding run.
      if (candidate.pid !== child.pid) return null;
      return candidate;
    }, 'server session', 90_000);
  } catch (error) { child.kill(); throw error; }
  const api = async (route, body) => {
    const response = await fetch(`http://127.0.0.1:${session.port}/api/${route}`, {
      method: body === undefined ? 'GET' : 'POST',
      headers: { 'X-Token': session.token, 'Content-Type': 'application/json' },
      body: body === undefined ? undefined : JSON.stringify(body), signal: AbortSignal.timeout(60_000),
    });
    const answer = await response.json();
    assert(response.ok, `${route}: ${JSON.stringify(answer)}`);
    return answer;
  };
  const on = () => until(async () => {
    assert.equal(child.exitCode, null, 'Server died');
    const state = await api('state');
    if (state.routing.status === 'error') throw new Error(JSON.stringify(state.routing));
    return state.routing.status === 'on' && state;
  }, 'routing on', 120_000);
  const quit = async () => {
    if (child.exitCode !== null) return;
    await api('quit', {});
    await until(() => child.exitCode !== null, 'server exit', 30_000);
    assert.equal(child.exitCode, 0, 'Server quit failed');
  };
  return { child, api, on, quit };
}

export async function verifyEngineProcess(options, dataDir) {
  const pid = Number((await readFile(path.join(dataDir, 'engine.pid'), 'utf8')).trim());
  assert(Number.isSafeInteger(pid) && pid > 0, 'Missing engine PID');
  const result = await run('powershell.exe', ['-NoProfile', '-Command',
    '$p = Get-CimInstance Win32_Process -Filter ("ProcessId=" + $env:TEST_ENGINE_PID); if (-not $p) { throw "Engine PID is gone" }; $p.ExecutablePath'],
  { env: { TEST_ENGINE_PID: String(pid) } });
  const observed = await realpath(result.stdout);
  assert.equal(observed.toLowerCase(), (await realpath(options.engine)).toLowerCase(), 'The running engine is not the requested executable');
  return { pid, path: observed };
}
