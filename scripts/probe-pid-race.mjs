// Temporary CI-only diagnosis. No sing-box, adapter, route or product change.
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { Engine } from '../lib/engine.mjs';

if (process.platform !== 'win32' || process.env.GITHUB_ACTIONS !== 'true' || process.env.RUNNER_ENVIRONMENT !== 'github-hosted') {
  throw new Error('PID diagnosis is restricted to disposable Windows CI runners.');
}
const dir = path.resolve('dist/pid-race');
await mkdir(dir, { recursive: true });
const file = path.join(dir, 'engine.pid');
for (const concurrent of [true, false]) {
  const errors = {};
  for (let i = 0; i < 10000; i++) {
    await writeFile(file, '1234');
    const results = concurrent
      ? await Promise.allSettled([rm(file, { force: true }), rm(file, { force: true })])
      : [await rm(file, { force: true }).then(() => ({ status: 'fulfilled' }), (reason) => ({ status: 'rejected', reason }))];
    for (const result of results) if (result.status === 'rejected') errors[result.reason.code] = (errors[result.reason.code] ?? 0) + 1;
  }
  console.log(`PID-FS ${JSON.stringify({ concurrent, runs: 10000, errors })}`);
}
for (const singleOwner of [false, true]) {
  const engine = new Engine({ singBoxPath: 'unused', dataDir: dir });
  if (singleOwner) {
    // Diagnostic control only: stopChild owns deliberate-stop cleanup.
    const original = engine.handleExit;
    engine.handleExit = function (child, code) {
      if (this.status === 'stopping') return;
      return original.call(this, child, code);
    };
  }
  let failures = 0, exited = 0, absentAfterFailure = 0;
  for (let i = 0; i < 200; i++) {
    const child = spawn(process.execPath, ['-e', "process.send('ready'); setInterval(() => {}, 1000)"], {
      windowsHide: true, stdio: ['ignore', 'ignore', 'ignore', 'ipc'],
    });
    engine.child = child;
    child.on('exit', (code) => { exited++; engine.handleExit(child, code); });
    await once(child, 'message');
    await writeFile(file, String(child.pid));
    engine.setStatus('on');
    try { await engine.stop(); }
    catch (error) {
      failures++;
      assert.notEqual(child.exitCode === null && child.signalCode === null, true);
      let stillAlive = true;
      try { process.kill(child.pid, 0); } catch (error) { if (error.code === 'ESRCH') stillAlive = false; else throw error; }
      let pidFile;
      try { pidFile = await readFile(file, 'utf8'); } catch (error) { pidFile = error.code; }
      if (pidFile === 'ENOENT') absentAfterFailure++;
      console.log(`PID-FAIL ${JSON.stringify({ singleOwner, iteration: i + 1, error: error.code, status: engine.status, stillAlive, pidFile })}`);
    }
  }
  console.log(`PID-ENGINE ${JSON.stringify({ singleOwner, runs: 200, exited, failures, absentAfterFailure })}`);
}
