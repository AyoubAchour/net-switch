import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { randomBytes, createHash } from 'node:crypto';
import { subscribe, unsubscribe } from 'node:diagnostics_channel';
import { createWriteStream } from 'node:fs';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import http from 'node:http';
import path from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';

export function hostedOnly() {
  assert(process.platform === 'win32' && process.env.GITHUB_ACTIONS === 'true' && process.env.RUNNER_ENVIRONMENT === 'github-hosted',
    'Network tests may run only on disposable GitHub-hosted Windows runners.');
}

export function run(exe, args, { env = {}, timeout = 60_000, failure = false } = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn(exe, args, { windowsHide: true, env: { ...process.env, ...env }, stdio: ['ignore', 'pipe', 'pipe'] });
    let stdout = '', stderr = '', expired = false;
    child.stdout.on('data', (chunk) => { stdout += chunk; });
    child.stderr.on('data', (chunk) => { stderr += chunk; });
    const timer = setTimeout(() => { expired = true; child.kill(); }, timeout);
    child.on('error', (error) => { clearTimeout(timer); reject(error); });
    child.on('close', (code) => {
      clearTimeout(timer);
      const result = { code, stdout: stdout.trim(), stderr: stderr.trim(), expired };
      if (expired || (code !== 0 && !failure)) reject(new Error(`${exe} ${args.join(' ')}: ${JSON.stringify(result)}`));
      else resolve(result);
    });
  });
}

export async function until(check, label, timeout = 30_000) {
  const end = Date.now() + timeout;
  let last;
  do {
    try { const value = await check(); if (value) return value; } catch (error) { last = error.message; }
    await delay(200);
  } while (Date.now() < end);
  throw new Error(`Timed out: ${label}${last ? `; ${last}` : ''}`);
}

export async function identity(exe, args = ['version']) {
  const absolute = path.resolve(exe);
  const version = await run(absolute, args);
  return { path: absolute, version: version.stdout, sha256: createHash('sha256').update(await readFile(absolute)).digest('hex') };
}

export async function startHarness(directory) {
  hostedOnly();
  const dir = path.resolve(directory);
  await mkdir(dir, { recursive: true });
  const exe = path.resolve('dist/windows-test/testisp.exe');
  const probeExe = path.resolve('dist/windows-test/testisp-probe.exe');
  const token = randomBytes(32).toString('hex');
  let state, processHandle;
  const network = async (action) => {
    // PowerShell 7, not Windows PowerShell: on the windows-11-arm runner every
    // powershell.exe that Node starts takes 22-28 s before its first line runs,
    // however it is spawned (run 39646376132), while pwsh.exe starts in 0.4 s.
    // The hosted images ship both; this script's cmdlets work in either.
    const result = await run('pwsh.exe', ['-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', path.resolve('tests/windows/testisp/network.ps1'), '-Action', action], {
      env: { TESTISP_INDEX: String(state?.index ?? ''), TESTISP_UPLINK: String(uplink?.index ?? ''), TESTISP_PROBE: probeExe },
    });
    return JSON.parse(result.stdout.replace(/^\uFEFF/, ''));
  };
  let uplink = null;
  uplink = await network('inspect');
  const binaries = { gateway: await identity(exe), probe: await identity(probeExe) };
  await writeFile(path.join(dir, 'executables.json'), JSON.stringify(binaries, null, 2));
  console.log(JSON.stringify({ binaries, uplink }));
  const log = createWriteStream(path.join(dir, 'testisp.log'));
  const stateFile = path.join(dir, `ready-${randomBytes(8).toString('hex')}.json`);
  processHandle = spawn(exe, ['serve', '--uplink-index', String(uplink.index), '--uplink-ip', uplink.address, '--state', stateFile], {
    windowsHide: true, env: { ...process.env, TESTISP_TOKEN: token }, stdio: ['ignore', 'pipe', 'pipe'],
  });
  processHandle.stdout.pipe(log, { end: false }); processHandle.stderr.pipe(log, { end: false });
  let spawnError;
  processHandle.on('error', (error) => { spawnError = error; });
  const exited = new Promise((resolve) => processHandle.on('close', resolve));
  let reservedAgent;
  const controlFetch = (url, options) => {
    if (!reservedAgent) return fetch(url, options);
    return new Promise((resolve, reject) => {
      const request = http.request(url, { ...options, agent: reservedAgent }, (response) => {
        const chunks = [];
        response.on('data', (chunk) => chunks.push(chunk));
        response.once('error', reject);
        response.once('end', () => resolve(new Response(Buffer.concat(chunks), { status: response.statusCode })));
      });
      request.once('error', reject);
      request.end(options.body);
    });
  };
  const httpEvents = [];
  const channels = ['client:beforeConnect', 'client:connected', 'client:sendHeaders', 'client:connectError', 'request:error'];
  const observers = channels.map((name) => {
    const observe = (event) => {
      if (!state) return;
      const origin = event.request?.origin;
      if (origin ? String(origin) !== state.control : event.connectParams?.host !== new URL(state.control).host) return;
      httpEvents.push({ at: new Date().toISOString(), event: name, path: event.request?.path,
        localPort: event.socket?.localPort, error: event.error?.message });
      if (httpEvents.length > 64) httpEvents.shift();
    };
    subscribe(`undici:${name}`, observe);
    return observe;
  });
  const control = async (endpoint, body) => {
    const started = performance.now();
    let phase = 'request';
    try {
      const response = await controlFetch(`${state.control}/${endpoint}`, { method: body === undefined ? 'GET' : 'POST',
        headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
        body: body === undefined ? undefined : JSON.stringify(body), signal: AbortSignal.timeout(5000) });
      phase = 'response';
      assert(response.ok, `${endpoint}: HTTP ${response.status}`);
      const result = await response.json();
      if (endpoint === 'diagnostics') {
        assert.equal(result.windowsTCP.error, 0, 'GetTcpStatistics failed; retransmit evidence is unavailable');
        assert(!result.ring.error, `GetIfEntry2Ex failed: ${result.ring.error}`);
      }
      return result;
    } catch (cause) {
      const evidence = { endpoint, phase, at: new Date().toISOString(), url: state?.control,
        elapsedMs: performance.now() - started, pid: processHandle.pid,
        exitCode: processHandle.exitCode, signal: processHandle.signalCode,
        code: cause.cause?.code ?? cause.code, cause: cause.cause?.message ?? cause.message,
        httpEvents: [...httpEvents],
        log: await readFile(path.join(dir, 'testisp.log'), 'utf8').then((value) => value.split('\n').slice(-40).join('\n')).catch(String) };
      // This is a separate read-only diagnostic request, never a retry of the
      // failed operation. Preserve the original error even if it succeeds.
      if (!['diagnostics', 'stop'].includes(endpoint) && processHandle.exitCode === null) {
        evidence.gateway = await control('diagnostics').then(({ at, heartbeat, gc, ring, session, windowsTCP }) =>
          ({ at, heartbeat, gc, ring, session, windowsTCP })).catch((error) => ({ error: error.message }));
      }
      console.error(`TestISP control failure ${JSON.stringify(evidence)}`);
      throw new Error(`TestISP ${endpoint}: ${JSON.stringify(evidence)}`, { cause });
    }
  };
  const reserveControl = async () => {
    assert(!reservedAgent, 'Control connection is already reserved');
    reservedAgent = new http.Agent({ keepAlive: true, maxSockets: 1, maxFreeSockets: 1 });
    const reservation = { connections: 0, localPort: null };
    const connect = reservedAgent.createConnection.bind(reservedAgent);
    reservedAgent.createConnection = (options, callback) => {
      assert.equal(reservation.connections, 0, 'The reserved control connection was lost; refusing a hidden reconnect');
      reservation.connections++;
      const socket = connect(options, callback);
      socket.once('connect', () => { reservation.localPort = socket.localPort; });
      return socket;
    };
    await control('capacity');
    assert(reservation.localPort, 'Control socket was not established before port pressure');
    return reservation;
  };
  // A caller's finally may close again after a failure. Preserve the first
  // pre-recovery snapshot and error instead of inspecting a recovered device.
  let closePromise;
  const close = (options) => closePromise ??= closeOnce(options);
  const closeOnce = async ({ crash = false } = {}) => {
    const errors = [];
    const evidence = { crash };
    let forced = false;
    try { await network('unblock-direct'); } catch (error) { errors.push(error); }
    if (crash) {
      try {
        evidence.before = await network('pnp');
        assert(evidence.before.some((d) => d.instanceID === state.instanceID && d.present), 'Crash probe requires our live adapter');
        assert(processHandle.kill(), 'Could not terminate the gateway we started');
      } catch (error) { errors.push(error); }
    } else if (state && processHandle.exitCode === null) {
      try { await control('stop', {}); } catch (error) { errors.push(error); }
    }
    if (processHandle.exitCode === null) {
      const timer = setTimeout(() => { forced = true; processHandle.kill(); }, 7000);
      await exited; clearTimeout(timer);
    }
    log.end();
    reservedAgent?.destroy();
    channels.forEach((name, i) => unsubscribe(`undici:${name}`, observers[i]));
    if (!crash) {
      try {
        // Get-PnpDevice includes non-present devices. Capture this before the
        // recovery process can remove a phantom left by an ordinary stop.
        evidence.normalExit = { code: processHandle.exitCode, signal: processHandle.signalCode, forced };
        evidence.afterNormalExit = await network('pnp');
        assert(!forced && processHandle.exitCode === 0, `TestISP did not exit normally: ${JSON.stringify(evidence.normalExit)}`);
        assert.equal(evidence.afterNormalExit.length, 0, `TestISP PnP devices remain after normal exit: ${JSON.stringify(evidence.afterNormalExit)}`);
        console.log('TestISP normal stop left no present or non-present PnP devices (before recovery)');
      } catch (error) { errors.push(error); }
    }
    if (crash) {
      try {
        evidence.orphan = await until(async () => {
          const devices = await network('pnp');
          return devices.some((d) => d.instanceID === state.instanceID && !d.present) && devices;
        }, 'our TestISP phantom before recovery');
      } catch (error) { errors.push(error); }
    }
    // The owner has exited. Recover only TestISP's fixed GUID in a fresh process;
    // this does not load the DLL or let its orphan sweeper hide cleanup defects.
    try {
      evidence.recovery = await run(exe, ['recover']);
      evidence.after = await network('pnp');
      assert.equal(evidence.after.length, 0, 'TestISP PnP devices remain after recovery');
      if (evidence.orphan) console.log('TestISP crash recovery removed the observed phantom device');
    } catch (error) { errors.push(error); }
    try { await until(() => network('clean').then(() => true), 'TestISP cleanup', 15_000); } catch (error) { errors.push(error); }
    evidence.errors = errors.map((error) => error.stack);
    await writeFile(path.join(dir, 'cleanup.json'), JSON.stringify(evidence, null, 2));
    if (errors.length) throw new AggregateError(errors, 'TestISP cleanup failed');
    return evidence;
  };
  try {
    state = await until(async () => {
      if (spawnError) throw spawnError;
      if (processHandle.exitCode !== null) throw new Error(`TestISP exited ${processHandle.exitCode}; see testisp.log`);
      return JSON.parse(await readFile(stateFile, 'utf8'));
    }, 'TestISP ready');
    await network('configure');
    await writeFile(path.join(dir, 'network.json'), JSON.stringify({ uplink, testisp: state }, null, 2));
    // failure: false, true (any failure before an HTTP response or TLS error),
    // or 'unreachable': the local TLS connect itself must be refused with
    // WSAENETUNREACH or WSAEHOSTUNREACH, as with no default route.
    const probe = async (line, failure = false, target) => {
      assert(failure !== 'unreachable' || target, 'Only local TLS probes report the connect phase');
      const nonce = randomBytes(16).toString('hex');
      const targetArgs = target ? ['--url', `https://${target.address}:${target.port}/?nonce=${nonce}`,
        '--ca', target.caFile, '--servername', 'netswitch.invalid'] : [];
      console.log(`TestISP probe start ${JSON.stringify({ at: new Date().toISOString(), line, failure })}`);
      const result = await run(probeExe, ['probe', ...targetArgs, ...(line ? ['--interface', String(line.index), '--source', line.address] : [])], { failure, timeout: 10_000 });
      console.log(`TestISP probe end ${JSON.stringify(result)}`);
      if (!failure) {
        const response = JSON.parse(result.stdout);
        assert.equal(response.verified, true, 'HTTPS peer identity was not verified');
        if (target) assert.equal(JSON.parse(response.body).nonce, nonce, 'Local TLS nonce missing');
        else assert.match(response.body, /(?:^|\n)ip=/, 'Real HTTPS trace body missing');
        return response;
      }
      assert.notEqual(result.code, 0, 'Failure injection did not stop the selected path');
      assert(!/HTTP [45]\d\d|certificate|x509:/i.test(result.stderr), 'Negative path check got an HTTP response or TLS setup failure');
      if (failure === 'unreachable') {
        assert.match(result.stderr, /local TLS failure: endpoint=\S+; phase=connect; winsock=100(?:51|65): /,
          'Expected the connect to fail at once as unreachable, not a timeout or a later failure');
      }
      return result;
    };
    return { uplink, testisp: state, control, reserveControl, diagnosticClient: { url: state.control, token }, network, probe, close };
  } catch (error) {
    try { await close(); }
    catch (cleanupError) { throw new AggregateError([error, cleanupError], 'TestISP startup and cleanup failed'); }
    throw error;
  }
}
