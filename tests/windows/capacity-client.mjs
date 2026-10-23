import assert from 'node:assert/strict';
import net from 'node:net';
import { emptyFillEvidence, openWithClientReattempt, windowsErrorName } from './tcp-fill.mjs';

assert(process.send, 'Use the hosted capacity runner');
const sockets = [];
const expectedClose = new WeakSet();
let lost = 0;
let survival, survivalTimer, survivalSent = 0, survivalReceived = 0, survivalMaxMs = 0, survivalError;
const status = () => ({ held: sockets.length, lost, live: sockets.filter((s) => !s.destroyed).length,
  survival: survival && { live: !survival.destroyed, sent: survivalSent, received: survivalReceived, maxMs: survivalMaxMs, error: survivalError } });
const hold = (socket) => {
  sockets.push(socket);
  socket.on('close', () => { if (!expectedClose.has(socket)) lost++; });
};
const closeSocket = (socket) => new Promise((resolve) => {
  if (socket.destroyed) { resolve(); return; }
  expectedClose.add(socket);
  socket.once('close', resolve);
  socket.end();
});
function echo(socket, value, timeout = 1000) {
  return new Promise((resolve, reject) => {
    const started = performance.now();
    const finish = (error, data) => {
      clearTimeout(timer); socket.off('data', dataHandler); socket.off('error', errorHandler);
      if (error) reject(error);
      else if (data.length !== 1 || data[0] !== value) reject(new Error('Capacity echo mismatch'));
      else resolve(performance.now() - started);
    };
    const dataHandler = (data) => finish(null, data), errorHandler = (error) => finish(error);
    const timer = setTimeout(() => finish(new Error('Held flow stopped responding')), timeout);
    socket.once('data', dataHandler); socket.once('error', errorHandler);
    socket.write(Buffer.from([value]));
  });
}
async function openOne({ host, port, localPort, timeout = 1000 }) {
  const started = performance.now();
  const tuple = (address, number) => address.includes(':') ? `[${address}]:${number}` : `${address}:${number}`;
  const remote = tuple(host, port);
  const socket = net.connect({ host, port, ...(localPort ? { localAddress: '198.18.0.1', localPort } : {}) });
  try {
    await new Promise((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error('Capacity handshake deadline')), timeout);
      socket.once('error', (error) => { clearTimeout(timer); reject(error); });
      socket.once('connect', () => { clearTimeout(timer); resolve(); });
    });
    await echo(socket, 0x71);
    socket.on('error', () => {}); // Close below records loss of an admitted flow.
    const ended = performance.now();
    return { socket, ms: ended - started, startMS: started, endMS: ended };
  } catch (error) {
    const ended = performance.now(), at = new Date().toISOString();
    // Keep the app's own error. Acceptance x64 job 120239285886 failed on one
    // client connect and could not say which Windows error it was.
    const local = socket.localPort && socket.localAddress ? tuple(socket.localAddress, socket.localPort)
      : (localPort ? tuple('198.18.0.1', localPort) : null);
    socket.destroy();
    return { failure: { source: 'client', code: error.code ?? 'DEADLINE', name: windowsErrorName(error.code ?? 'DEADLINE'),
      errno: error.errno ?? null, call: error.syscall, message: error.message, local, remote, at,
      ms: ended - started, startMS: started, endMS: ended }, ms: ended - started, startMS: started, endMS: ended };
  }
}
process.on('message', async ({ id, command, host, ports, count, localPort = 45000, keep = false, timeout = 1000, all = false, batch = 0 }) => {
  try {
    if (command === 'open') {
      // Filling to the OS limit stops at the first refused batch; recovery
      // (all) attempts every flow once, so each refusal is its own record.
      // Each attempt's own start and end on this process's clock, so a
      // reopen is timed alone and a re-attempt from its original start.
      // The ordinary fill gives a client-side port allocation refusal one
      // reported re-attempt on a fresh socket (SYSTEM-DESIGN 5.9 amended);
      // recovery already re-attempts its refused first attempts in the parent.
      const fill = emptyFillEvidence();
      const failures = [], attempts = [];
      let opened = 0, batches = 0;
      for (let n = 0; n < count; n += 32) {
        batches++;
        await Promise.all(Array.from({ length: Math.min(32, count - n) }, async (_, k) => {
          const open = () => openOne({ host, port: ports[(sockets.length + k) % ports.length], timeout });
          const result = all ? await open() : await openWithClientReattempt({ open, evidence: fill,
            request: id, batch: batch + batches - 1, attempt: n + k });
          if (result.failure) {
            failures.push(result.failure);
            attempts.push({ startMS: result.startMS, endMS: result.endMS, ok: false });
          } else {
            hold(result.socket);
            opened++;
            attempts.push({ startMS: result.startMS, endMS: result.endMS, ok: true });
          }
        }));
        if (failures.length && !all) break;
      }
      process.send({ id, result: { ...status(), opened, failures, attempts, batches, fill } });
    } else if (command === 'probe') {
      // A fixed app-side port outside the dynamic pool lets this SYN reach
      // the engine even when an ordinary app cannot allocate another port.
      const { socket, failure, ms } = await openOne({ host, port: ports[0], localPort, timeout });
      if (socket) {
        if (keep) hold(socket);
        else await closeSocket(socket);
      }
      process.send({ id, result: { ...(failure ?? { code: 'OK', ms }), localPort } });
    } else if (command === 'verify') {
      let maxMs = 0;
      for (let n = 0; n < sockets.length; n += 128) {
        const times = await Promise.all(sockets.slice(n, n + 128).map((socket) => echo(socket, 0x72)));
        maxMs = Math.max(maxMs, ...times);
      }
      process.send({ id, result: { ...status(), checked: sockets.length, maxMs } });
    } else if (command === 'survival') {
      const result = await openOne({ host, port: ports[0] });
      assert(result.socket, JSON.stringify(result.failure));
      survival = result.socket;
      survivalTimer = setInterval(async () => {
        if (survivalSent !== survivalReceived || survivalError) return;
        survivalSent++;
        try {
          survivalMaxMs = Math.max(survivalMaxMs, await echo(survival, 0x73));
          survivalReceived++;
        } catch (error) { survivalError = error.message; }
      }, 100);
      process.send({ id, result: status() });
    } else if (command === 'release') {
      const removed = sockets.splice(0, count);
      const localPorts = removed.map((socket) => socket.localPort);
      await Promise.all(removed.map(closeSocket));
      process.send({ id, result: { ...status(), released: removed.length, localPorts } });
    } else if (command === 'status') {
      process.send({ id, result: status() });
    } else if (command === 'close') {
      clearInterval(survivalTimer);
      if (survival) await closeSocket(survival);
      await Promise.all(sockets.map(closeSocket));
      process.send({ id, result: { closed: sockets.length } });
    } else throw new Error('Unknown capacity action');
  } catch (error) { process.send({ id, error: error.stack }); }
});
process.on('disconnect', () => { for (const socket of sockets) socket.destroy(); process.exit(0); });
