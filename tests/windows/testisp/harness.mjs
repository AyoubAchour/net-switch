import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { randomBytes, createHash } from 'node:crypto';
import { createWriteStream } from 'node:fs';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
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
    const result = await run('powershell.exe', ['-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', path.resolve('tests/windows/testisp/network.ps1'), '-Action', action], {
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
  const control = async (endpoint, body) => {
    const response = await fetch(`${state.control}/${endpoint}`, { method: body === undefined ? 'GET' : 'POST',
      headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
      body: body === undefined ? undefined : JSON.stringify(body), signal: AbortSignal.timeout(5000) });
    assert(response.ok, `${endpoint}: HTTP ${response.status}`);
    const result = await response.json();
    if (endpoint === 'diagnostics') {
      assert.equal(result.windowsTCP.error, 0, 'GetTcpStatistics failed; retransmit evidence is unavailable');
      assert(!result.ring.error, `GetIfEntry2Ex failed: ${result.ring.error}`);
    }
    return result;
  };
  const close = async ({ crash = false } = {}) => {
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
    const probe = async (line, failure = false) => {
      const result = await run(probeExe, ['probe', ...(line ? ['--interface', String(line.index), '--source', line.address] : [])], { failure, timeout: 10_000 });
      if (!failure) {
        const response = JSON.parse(result.stdout);
        assert.match(response.body, /(?:^|\n)ip=/, 'Real HTTPS trace body missing');
        return response;
      }
      assert.notEqual(result.code, 0, 'Failure injection did not stop the selected path');
      return result;
    };
    return { uplink, testisp: state, control, diagnosticClient: { url: state.control, token }, network, probe, close };
  } catch (error) { await close(); throw error; }
}
