import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { existsSync, mkdtempSync, readFileSync, rmSync, unlinkSync, writeFileSync } from 'node:fs';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import { before, test } from 'node:test';
import { fileURLToPath } from 'node:url';

// The tray icon as a program of its own (tray\bin\NetSwitchTray.exe, built by
// npm run build:tray). These tests start it for a few seconds on a temporary
// data folder, so an icon may show briefly. From such a folder it never starts
// Net Switch. Each test ends the copies it started: by removing server.json,
// which makes the icon leave by itself, or else by their own process IDs.
const ROOT = fileURLToPath(new URL('..', import.meta.url));
const TRAY = path.join(ROOT, 'tray', 'bin', 'NetSwitchTray.exe');
const POWERSHELL = path.join(process.env.SystemRoot ?? 'C:\\Windows', 'System32', 'WindowsPowerShell', 'v1.0', 'powershell.exe');
const needsTray = {
  skip: process.platform !== 'win32' || (existsSync(TRAY) ? false : 'tray\\bin\\NetSwitchTray.exe is not built; run npm run build:tray'),
  timeout: 60_000,
};

// The exit code, or 'still running' after ms.
async function exitWithin(run, ms) {
  const controller = new AbortController();
  try {
    return await Promise.race([run.exited, delay(ms, 'still running', { signal: controller.signal })]);
  } finally {
    controller.abort();
  }
}

// The frozen 0.3.x AnyCPU tray loads the emulated x64 CLR on ARM64. On fresh
// runners, cold CLR startup/JIT took 5-14.6 seconds before Main ran. Launch it
// once outside the behaviour tests' clocks, with a 60-second cold-start budget.
// Bad arguments return before touching any data folder. This is not a retry:
// a failed warm-up fails the suite, and all existing case deadlines stay put.
// Keep its duration visible rather than hiding cold-start cost in a timeout.
before(async () => {
  if (needsTray.skip) return;
  const started = performance.now();
  const child = spawn(TRAY, ['--data-dir'], { stdio: 'ignore' });
  const run = { exited: once(child, 'exit').then(([code]) => code) };
  try {
    assert.equal(await exitWithin(run, 60_000), 2, 'tray warm-up must exit with code 2 within 60 seconds');
  } finally {
    console.log(`tray warm-up: ${Math.round(performance.now() - started)} ms; exit=${child.exitCode}; signal=${child.signalCode}`);
    if (child.exitCode === null && child.signalCode === null) child.kill();
    assert.notEqual(await exitWithin(run, 5000), 'still running', 'tray warm-up survived cleanup');
  }
}, { timeout: 70_000 });

// A temporary data folder, and a start() whose processes are stopped (only
// if still running) and waited for before the folder is removed.
function setup(t) {
  const dir = mkdtempSync(path.join(os.tmpdir(), 'netswitch-tray-'));
  const runs = [];
  t.after(async () => {
    // Save evidence before killing a timed-out process or deleting its log.
    // A timeout before "started" needs a different investigation from one
    // after the tray has logged that Net Switch is no longer running.
    for (const run of runs) {
      t.diagnostic(JSON.stringify({ ...run.timing, pid: run.child.pid,
        exitCode: run.child.exitCode, signalCode: run.child.signalCode,
        elapsedMs: Math.round(performance.now() - run.started) }));
    }
    t.diagnostic(`tray.log before cleanup: ${log() || '(not written)'}`);
    for (const run of runs) {
      if (run.child.exitCode === null && run.child.signalCode === null) {
        t.diagnostic(`stopping test process ${run.child.pid}`);
        run.child.kill();
      }
    }
    const exits = await Promise.all(runs.map((run) => exitWithin(run, 5000)));
    for (let i = 0; i < runs.length; i++) {
      assert.notEqual(exits[i], 'still running', `test process ${runs[i].child.pid} survived cleanup`);
    }
    rmSync(dir, { recursive: true, force: true, maxRetries: 10, retryDelay: 200 });
  });
  const start = (file, args, options = {}) => {
    const started = performance.now();
    const timing = { file: path.basename(file), startedAt: new Date().toISOString() };
    const child = spawn(file, args, { stdio: 'ignore', ...options });
    const elapsed = () => Math.round(performance.now() - started);
    timing.spawnReturnedMs = elapsed();
    child.once('spawn', () => { timing.spawnEventMs = elapsed(); });
    const run = { child, started, timing, exited: once(child, 'exit').then(([code]) => {
      timing.exitMs = elapsed();
      return code;
    }) };
    runs.push(run);
    return run;
  };
  const log = () => {
    const file = path.join(dir, 'tray.log');
    return existsSync(file) ? readFileSync(file, 'utf8') : '';
  };
  return { dir, start, log };
}

// A port nothing listens on, so a reading is refused at once.
async function closedPort() {
  const server = net.createServer().listen(0, '127.0.0.1');
  await once(server, 'listening');
  const { port } = server.address();
  server.close();
  await once(server, 'close');
  return port;
}

test('arguments the tray program doesn’t know make it leave at once with code 2', needsTray, async (t) => {
  const { start } = setup(t);
  assert.equal(await exitWithin(start(TRAY, ['--data-dir']), 15_000), 2);
});

test('with no Net Switch to watch, the tray program starts, logs it, and leaves by itself', needsTray, async (t) => {
  const { dir, start, log } = setup(t);
  // A relative -DataDir is taken from the app folder, as tray.ps1 takes it.
  const run = start(TRAY, ['-DataDir', path.relative(ROOT, dir)]);
  // No server.json on two readings a second apart means Net Switch isn't running.
  assert.equal(await exitWithin(run, 20_000), 0);
  assert.match(log(), / started\r?\n/);
  assert.match(log(), / Net Switch is no longer running\r?\n/);
  assert.match(log(), / stopped\r?\n/);
});

test('one icon per data folder: another copy, or tray.ps1, leaves at once while the first keeps running', needsTray, async (t) => {
  const { dir, start, log } = setup(t);
  const serverFile = path.join(dir, 'server.json');
  // A Net Switch that ended without cleaning up: nothing answers on its port
  // and no process has its ID, so the icon says it isn't running, and stays.
  writeFileSync(serverFile, JSON.stringify({ port: await closedPort(), token: 'test', pid: 0 }));
  const first = start(TRAY, ['-DataDir', dir]);
  for (let waited = 0; !/ started\r?\n/.test(log()); waited += 100) {
    assert.ok(waited < 15_000, 'the tray program did not start within 15 seconds');
    assert.equal(first.child.exitCode, null, 'the tray program ended early');
    await delay(100);
  }

  assert.equal(await exitWithin(start(TRAY, ['-DataDir', dir]), 15_000), 0);
  // tray.ps1 names the folder's mutex the same way, so it leaves before compiling anything.
  const script = start(POWERSHELL, ['-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', path.join(ROOT, 'tray.ps1'), '-DataDir', dir], { windowsHide: true });
  assert.equal(await exitWithin(script, 30_000), 0);
  await delay(1500);
  assert.equal(first.child.exitCode, null, 'the first copy keeps running');
  assert.equal(log().match(/ started\r?\n/g).length, 1, 'only the first copy started an icon');

  // Net Switch removes server.json when it quits; that is how the icon learns it.
  unlinkSync(serverFile);
  assert.equal(await exitWithin(first, 20_000), 0);
  assert.match(log(), / Net Switch is no longer running\r?\n/);
});
