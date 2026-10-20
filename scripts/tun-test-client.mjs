// Launched by e2e-tun.mjs using a separate copy of Node, so process pins are real.
import { Agent, request } from 'node:https';
import { connect, createServer } from 'node:net';
import { setTimeout as delay } from 'node:timers/promises';
import assert from 'node:assert/strict';
import { createSocket } from 'node:dgram';
import { randomBytes } from 'node:crypto';

if (!process.send) throw new Error('Run this client through e2e-tun.mjs');
const held = new Map();
let next = 0;
async function requestOn(item) {
  const nonce = randomBytes(16).toString('hex');
  const label = 'Local HTTPS';
  return new Promise((resolve, reject) => {
    const req = request({ ...item.target,
      path: `/?nonce=${nonce}`,
      agent: item.agent, signal: AbortSignal.timeout(10_000) }, (res) => {
      const port = res.socket.localPort;
      let body = '';
      res.setEncoding('utf8');
      res.on('data', (chunk) => { body += chunk; });
      res.on('error', reject);
      res.on('end', () => {
        try {
          assert.equal(res.statusCode, 200, `${label} HTTP ${res.statusCode}: ${body.slice(0, 100)}`);
          const reply = JSON.parse(body);
          assert.equal(reply.nonce, nonce, 'Local HTTPS response did not echo this request');
          assert(Number.isInteger(reply.connection), 'Missing responder connection identity');
          const connection = reply.connection;
          if (item.port) {
            assert(req.reusedSocket && item.port === port && item.connection === connection,
              `Connection ${item.id} was replaced`);
          }
          item.port = port;
          item.connection = connection;
          resolve({ id: item.id, port, bytes: body.length, reused: req.reusedSocket, connection });
        } catch (error) { reject(error); }
      });
    });
    req.on('socket', (socket) => {
      if (item.socket === socket) return;
      item.socket = socket;
      const event = (name, extra = {}) => {
        const detail = { at: new Date().toISOString(), event: name, id: item.id,
          port: item.port ?? socket.localPort, connection: item.connection, ...extra };
        item.events.push(detail);
        console.log(`TLS socket: ${JSON.stringify(detail)}`);
      };
      socket.on('end', () => event('peer FIN'));
      socket.on('error', (error) => event('error', { code: error.code, message: error.message }));
      socket.on('close', (hadError) => event('close', { hadError, requestedByTest: !!item.closing }));
    });
    req.on('error', (cause) => reject(new Error(`${label} ${item.target.host}:${item.target.port}, connection ${item.id}: ${cause.message}`, { cause })));
    req.end();
  });
}
async function open(count, target) {
  assert(target?.ca && target.servername === 'netswitch.invalid',
    'A local TLS target with its certificate is required');
  const results = [];
  // Keep the existing concurrency and request deadline.
  for (let n = 0; n < count; n += 10) {
    results.push(...await Promise.all(Array.from({ length: Math.min(10, count - n) }, async () => {
      const item = { id: ++next, target, events: [], agent: new Agent({ keepAlive: true, maxSockets: 1, maxFreeSockets: 1 }) };
      held.set(item.id, item);
      return requestOn(item);
    })));
  }
  return results;
}
async function reuseProbe(target, localAddress) {
  assert(target?.host && target.port, 'A local HTTP target is required');
  const port = await new Promise((resolve, reject) => {
    const server = createServer();
    server.on('error', reject);
    server.listen(0, '0.0.0.0', () => {
      const value = server.address().port;
      server.close(() => resolve(value));
    });
  });
  const attempts = [];
  for (let n = 0; n < 4; n += 1) {
    attempts.push(await new Promise((resolve) => {
      const started = performance.now();
      let connected = false, remoteClosedFirst = false, response = '', source;
      const socket = connect({ host: target.host, port: target.port, localAddress, localPort: port, allowHalfOpen: true });
      const timer = setTimeout(() => finish('timeout'), 5000);
      let done = false;
      function finish(outcome) {
        if (done) return;
        done = true;
        clearTimeout(timer);
        socket.destroy();
        resolve({ attempt: n + 1, port, source, connected, remoteClosedFirst,
          outcome, ms: Math.round(performance.now() - started), status: response.split('\r\n')[0] });
      }
      socket.on('connect', () => {
        connected = true;
        source = socket.localAddress;
        socket.write('GET /close HTTP/1.1\r\nHost: netswitch.invalid\r\nConnection: close\r\n\r\n');
      });
      socket.on('data', (data) => { response += data; });
      socket.on('end', () => { remoteClosedFirst = true; socket.end(); });
      socket.on('close', () => finish(remoteClosedFirst ? 'closed' : 'closed-without-fin'));
      socket.on('error', (error) => finish(error.code ?? error.message));
    }));
    await delay(500);
  }
  return attempts;
}
async function udp(size, target, localAddress) {
  assert(target?.host && target.port, 'An explicit local UDP target is required');
  const socket = createSocket('udp4');
  // A real DNS query with RFC 7830 EDNS padding, including a >1500-byte packet.
  const question = Buffer.from('076578616d706c6503636f6d0000010001', 'hex');
  const header = Buffer.from('123401000001000000000001', 'hex');
  const padding = Math.max(0, size - header.length - question.length - 15);
  const opt = Buffer.alloc(15 + padding);
  opt.writeUInt16BE(41, 1); opt.writeUInt16BE(4096, 3);
  opt.writeUInt16BE(4 + padding, 9); opt.writeUInt16BE(12, 11); opt.writeUInt16BE(padding, 13);
  const packet = Buffer.concat([header, question, opt]);
  try {
    return await new Promise((resolve, reject) => {
      const servers = [target.host];
      let attempts = 0, done = false;
      const send = () => {
        // Five attempts per resolver, one each second. Keep the same socket
        // and large payload so this still exercises real UDP TUN routing.
        if (attempts === servers.length * 5) {
          finish(reject, new Error(`No UDP DNS reply to ${packet.length} bytes after ${attempts} attempts`));
          return;
        }
        socket.send(packet, target.port, servers[Math.floor(attempts++ / 5)]);
      };
      const timer = setInterval(send, 1000);
      const finish = (fn, value) => { if (done) return; done = true; clearInterval(timer); fn(value); };
      socket.on('error', (error) => finish(reject, error));
      socket.on('message', (reply, peer) => {
        if (!servers.includes(peer.address) || peer.port !== target.port || reply.length < 12 || reply.readUInt16BE(0) !== 0x1234) return;
        try {
          assert(reply[2] & 0x80, 'DNS response flag missing');
          assert.equal(reply[3] & 15, 0, 'DNS error response');
          finish(resolve, { sent: packet.length, received: reply.length, port: socket.address().port });
        } catch (error) { finish(reject, error); }
      });
      socket.bind(0, localAddress ?? '0.0.0.0', send);
    });
  } finally { socket.close(); }
}
process.on('message', async ({ id, command, count, ids, size, target, localAddress }) => {
  try {
    let result;
    if (command === 'open') result = await open(count, target);
    else if (command === 'refresh') result = await Promise.all(ids.map((key) => requestOn(held.get(key))));
    else if (command === 'reuse') result = await reuseProbe(target, localAddress);
    else if (command === 'udp') result = await udp(size, target, localAddress);
    else if (command === 'diagnostics') result = [...held.values()].map(({ id, port, connection, events, socket }) =>
      ({ id, port, connection, events, destroyed: socket?.destroyed, bytesRead: socket?.bytesRead, bytesWritten: socket?.bytesWritten }));
    else if (command === 'close') { for (const item of held.values()) { item.closing = true; item.agent.destroy(); } held.clear(); result = true; }
    else throw new Error(`Unknown command ${command}`);
    process.send({ id, result });
  } catch (error) { process.send({ id, error: error.stack }); }
});
process.on('disconnect', () => { for (const item of held.values()) item.agent.destroy(); process.exit(); });
