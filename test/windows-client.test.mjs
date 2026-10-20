import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { createServer } from 'node:http';
import { fileURLToPath } from 'node:url';
import test from 'node:test';

test('a timed-out parallel HTTP request retains its own tuple and response phase', { timeout: 25_000 }, async (t) => {
  const observed = [];
  const server = createServer((req, res) => {
    const nonce = new URL(req.url, 'http://fixture').searchParams.get('nonce');
    observed.push({ nonce, port: req.socket.remotePort });
    if (observed.length === 1) {
      res.end(JSON.stringify({ nonce }));
    } else {
      // Deliver headers and an incomplete body. The other request succeeds,
      // so a generic AbortError cannot tell these two connections apart.
      res.writeHead(200, { 'Content-Length': '100' });
      res.write('{');
    }
  });
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  const worker = spawn(process.execPath, [fileURLToPath(new URL('../tests/windows/client.mjs', import.meta.url))], {
    windowsHide: true, stdio: ['ignore', 'ignore', 'pipe', 'ipc'],
  });
  const closed = once(worker, 'close');
  const pending = new Map();
  let serial = 0, stderr = '';
  worker.stderr.on('data', (chunk) => { stderr += chunk; });
  worker.on('message', ({ id, result, error }) => {
    const entry = pending.get(id);
    if (!entry) return;
    pending.delete(id);
    if (error) entry.reject(new Error(error)); else entry.resolve(result);
  });
  worker.on('exit', (code) => {
    for (const entry of pending.values()) entry.reject(new Error(`Client exited ${code}: ${stderr}`));
    pending.clear();
  });
  const call = (command, args = {}) => new Promise((resolve, reject) => {
    const id = ++serial;
    pending.set(id, { resolve, reject });
    worker.send({ id, command, ...args });
  });
  t.after(async () => {
    worker.kill();
    server.closeAllConnections();
    await Promise.all([closed, new Promise((resolve) => server.close(resolve))]);
  });
  await assert.rejects(call('open', { count: 2, target: { host: '127.0.0.1', http: server.address().port } }), /HTTP request failed:.*"phase":"response"/);
  const history = await call('requests');
  assert.equal(observed.length, 2, 'The two actual requests must reach the fixture');
  assert.equal(history.length, 2);
  const complete = history.find((entry) => entry.phase === 'complete');
  const failed = history.find((entry) => entry.error);
  assert(complete);
  assert(failed);
  assert.equal(failed.code, 'ABORT_ERR');
  assert.equal(failed.phase, 'response');
  assert.equal(failed.statusCode, 200);
  assert.equal(failed.bytesReceived, 1);
  assert(failed.elapsedMs >= 7900, 'The unchanged eight-second request deadline must actually expire');
  assert(failed.timings.response >= failed.timings['tcp-connected']);
  assert.equal(failed.localPort, observed.find((entry) => entry.nonce === failed.nonce).port);
  assert.notEqual(failed.nonce, complete.nonce);
});
