// Launched by e2e-tun.mjs using a separate copy of Node, so process pins are real.
import assert from 'node:assert/strict';
import { createSocket } from 'node:dgram';
import { Agent, request } from 'node:https';
import { connect, createServer } from 'node:net';
import { setTimeout as delay } from 'node:timers/promises';

if (!process.send) throw new Error('Run this client through e2e-tun.mjs');
const held = new Map();
let next = 0;
async function requestOn(item) {
  return new Promise((resolve, reject) => {
    const req = request({ host: '1.1.1.1', port: 443, servername: 'one.one.one.one',
      path: '/cdn-cgi/trace', agent: item.agent, signal: AbortSignal.timeout(10_000) }, (res) => {
      const port = res.socket.localPort;
      let body = '';
      res.setEncoding('utf8');
      res.on('data', (chunk) => { body += chunk; });
      res.on('error', reject);
      res.on('end', () => {
        if (res.statusCode !== 200 || !body.includes('ip=')) return reject(new Error(`HTTP ${res.statusCode}: ${body.slice(0,100)}`));
        if (item.port && (!req.reusedSocket || item.port !== port)) return reject(new Error(`Connection ${item.id} was replaced`));
        item.port = port;
        resolve({ id: item.id, port, bytes: body.length, reused: req.reusedSocket });
      });
    });
    req.on('error', reject);
    req.end();
  });
}
async function open(count) {
  const results = [];
  // Ten at a time limits load on the public endpoint and runner.
  for (let n = 0; n < count; n += 10) {
    results.push(...await Promise.all(Array.from({ length: Math.min(10, count - n) }, async () => {
      const item = { id: ++next, agent: new Agent({ keepAlive: true, maxSockets: 1, maxFreeSockets: 1 }) };
      held.set(item.id, item);
      return requestOn(item);
    })));
  }
  return results;
}
async function reuseProbe() {
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
      const socket = connect({ host: '1.1.1.1', port: 80, localPort: port, allowHalfOpen: true });
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
        socket.write('GET /cdn-cgi/trace HTTP/1.1\r\nHost: one.one.one.one\r\nConnection: close\r\n\r\n');
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
async function udp(size, target = { host: '1.1.1.1', port: 53 }, localAddress) {
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
      const timer = setTimeout(() => reject(new Error(`No UDP DNS reply to ${packet.length} bytes`)), 5000);
      const finish = (fn, value) => { clearTimeout(timer); fn(value); };
      socket.on('error', (error) => finish(reject, error));
      socket.on('message', (reply, peer) => {
        if (peer.address !== target.host || peer.port !== target.port || reply.length < 12 || reply.readUInt16BE(0) !== 0x1234) return;
        try {
          assert(reply[2] & 0x80, 'DNS response flag missing');
          assert.equal(reply[3] & 15, 0, 'DNS error response');
          finish(resolve, { sent: packet.length, received: reply.length, port: socket.address().port });
        } catch (error) { finish(reject, error); }
      });
      socket.bind(0, localAddress ?? '0.0.0.0', () => socket.send(packet, target.port, target.host));
    });
  } finally { socket.close(); }
}
process.on('message', async ({ id, command, count, ids, size, target, localAddress }) => {
  try {
    let result;
    if (command === 'open') result = await open(count);
    else if (command === 'refresh') result = await Promise.all(ids.map((key) => requestOn(held.get(key))));
    else if (command === 'reuse') result = await reuseProbe();
    else if (command === 'udp') result = await udp(size, target, localAddress);
    else if (command === 'close') { for (const item of held.values()) item.agent.destroy(); held.clear(); result = true; }
    else throw new Error(`Unknown command ${command}`);
    process.send({ id, result });
  } catch (error) { process.send({ id, error: error.stack }); }
});
process.on('disconnect', () => { for (const item of held.values()) item.agent.destroy(); process.exit(); });
