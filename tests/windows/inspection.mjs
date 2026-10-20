import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import path from 'node:path';
import { createInterface } from 'node:readline';
import { hostedOnly } from './testisp/harness.mjs';

export async function startInspection() {
  hostedOnly();
  const child = spawn('powershell.exe', ['-NoProfile', '-File', path.resolve('tests/windows/inspection-worker.ps1')],
    { windowsHide: true, stdio: ['pipe', 'pipe', 'pipe'] });
  const pending = new Map();
  let serial = 0, stderr = '';
  let resolveReady, rejectReady;
  const ready = new Promise((resolve, reject) => { resolveReady = resolve; rejectReady = reject; });
  const fail = (error) => {
    rejectReady(error);
    for (const item of pending.values()) { clearTimeout(item.timer); item.reject(error); }
    pending.clear();
  };
  child.on('error', fail);
  child.stdin.on('error', fail);
  child.on('exit', (code) => fail(new Error(`Inspection process exited ${code}: ${stderr}`)));
  child.stderr.on('data', (chunk) => { stderr = (stderr + chunk).slice(-8192); });
  const lines = createInterface({ input: child.stdout });
  lines.on('line', (line) => {
    try {
      const message = JSON.parse(line.replace(/^\uFEFF/, ''));
      if (message.ready) { resolveReady(message); return; }
      const item = pending.get(message.id);
      assert(item, `Unexpected inspection response ${message.id}`);
      pending.delete(message.id); clearTimeout(item.timer);
      if (message.error) item.reject(new Error(message.error));
      else item.resolve(message.body ? JSON.parse(message.body) : []);
    } catch (error) { fail(error); }
  });
  const readyTimer = setTimeout(() => { fail(new Error('Inspection process did not start')); child.kill(); }, 90_000);
  try { await ready; } finally { clearTimeout(readyTimer); }
  return {
    query(action) {
      assert(['network', 'pnp'].includes(action));
      return new Promise((resolve, reject) => {
        const id = ++serial;
        const timer = setTimeout(() => { pending.delete(id); reject(new Error(`Inspection ${action} timed out: ${stderr}`)); }, 90_000);
        pending.set(id, { resolve, reject, timer });
        child.stdin.write(JSON.stringify({ id, action }) + '\n');
      });
    },
    async close() {
      child.stdin.end();
      try {
        if (child.exitCode === null && child.signalCode === null) {
          await once(child, 'exit', { signal: AbortSignal.timeout(5000) });
        }
        assert.equal(child.exitCode, 0, 'Inspection process failed');
      } finally {
        lines.close();
        if (child.exitCode === null && child.signalCode === null) child.kill();
      }
    },
  };
}
