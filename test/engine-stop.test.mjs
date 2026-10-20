import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { createInterface } from 'node:readline';
import test from 'node:test';
import { Engine } from '../lib/engine.mjs';
import { windows } from '../lib/platform/windows.mjs';

async function firstLine(child) {
  let errors = '';
  child.stderr?.on('data', data => { errors += data; });
  const lines = createInterface({ input: child.stdout, crlfDelay: Infinity });
  try {
    const [line] = await once(lines, 'line', { signal: AbortSignal.timeout(10_000) });
    return line;
  } catch (error) {
    throw new Error(`child did not become ready: ${errors}`, { cause: error });
  } finally {
    lines.close();
  }
}

async function fixture(t, platform = windows) {
  const dir = await mkdtemp(path.join(tmpdir(), 'netswitch-engine-stop-'));
  t.after(async () => {
    assert.equal(path.dirname(path.resolve(dir)), path.resolve(tmpdir()));
    assert.ok(path.basename(dir).startsWith('netswitch-engine-stop-'));
    await rm(dir, { recursive: true, force: true });
  });
  return new Engine({ dataDir: dir, singBoxPath: process.execPath, mode: 'proxy', platform });
}

test('a locked PID file cannot turn a confirmed engine stop into a failure', { skip: process.platform !== 'win32', timeout: 20_000 }, async t => {
  const engine = await fixture(t);
  const owned = [];
  try {
    // Only a harmless Node child is started. No engine, TUN or routing is used.
    const child = spawn(process.execPath, ['-e', "console.log('ready'); setInterval(() => {}, 1000)"], { windowsHide: true, stdio: ['ignore', 'pipe', 'pipe'] });
    owned.push(child);
    assert.equal(await firstLine(child), 'ready');
    engine.child = child;
    engine.setStatus('on');
    child.on('exit', code => engine.handleExit(child, code));
    await writeFile(engine.pidPath, String(child.pid));

    // Windows permits reads/writes but refuses deletion while this handle is
    // open. This is a real filesystem failure, not a mocked rm result.
    const holder = spawn('powershell.exe', ['-NoProfile', '-Command',
      "$ErrorActionPreference = 'Stop'; $heldPID = [IO.File]::Open($env:NETSWITCH_TEST_LOCK_FILE, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite); try { [Console]::WriteLine('locked'); [Console]::In.ReadLine() | Out-Null } finally { $heldPID.Dispose() }"],
    { windowsHide: true, stdio: ['pipe', 'pipe', 'pipe'], env: { ...process.env, NETSWITCH_TEST_LOCK_FILE: engine.pidPath } });
    owned.push(holder);
    assert.equal(await firstLine(holder), 'locked');
    assert.equal(await readFile(engine.pidPath, 'utf8'), String(child.pid));
    await assert.rejects(rm(engine.pidPath, { force: true }), error => ['EPERM', 'EBUSY', 'EACCES'].includes(error.code));
    assert.equal(child.exitCode, null);
    assert.equal(child.signalCode, null);

    await engine.stop();
    assert.ok(child.exitCode !== null || child.signalCode !== null, 'the owned process must really exit');
    assert.equal(engine.child, null);
    assert.equal(engine.status, 'off');
    assert.equal(await readFile(engine.pidPath, 'utf8'), String(child.pid), 'the lock must still be active');
    assert.match(await readFile(engine.logPath, 'utf8'), /stale engine PID.*(EPERM|EBUSY|EACCES)/i);
  } finally {
    // Release test-owned helpers even when an assertion fails, before the
    // temporary-directory cleanup hook tries to remove the locked file.
    for (const child of owned.reverse()) {
      if (child.exitCode === null && child.signalCode === null) {
        const exited = once(child, 'exit');
        child.kill();
        await exited;
      }
    }
  }
});

test('a genuine orphan-stop failure stays fatal and preserves its recovery record', async t => {
  const engine = await fixture(t, { ...windows, stopOrphan: async () => { throw new Error('owned engine is still running'); } });
  await writeFile(engine.pidPath, '1234');
  await assert.rejects(engine.stop(), /owned engine is still running/);
  assert.equal(engine.status, 'error');
  assert.equal(await readFile(engine.pidPath, 'utf8'), '1234');
});
