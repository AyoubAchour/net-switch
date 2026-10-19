// Launched by e2e-tun.mjs using a separate copy of Node, so process pins are real.
import { Agent, request } from 'node:https';
import { connect, createServer } from 'node:net';
import { setTimeout as delay } from 'node:timers/promises';
import { udpProbe } from './tun-test-dns.mjs';

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
process.on('message', async ({ id, command, count, ids, size, server, port }) => {
  try {
    let result;
    if (command === 'open') result = await open(count);
    else if (command === 'refresh') result = await Promise.all(ids.map((key) => requestOn(held.get(key))));
    else if (command === 'reuse') result = await reuseProbe();
    else if (command === 'udp') result = await udpProbe({ size, server, port });
    else if (command === 'close') { for (const item of held.values()) item.agent.destroy(); held.clear(); result = true; }
    else throw new Error(`Unknown command ${command}`);
    process.send({ id, result });
  } catch (error) { process.send({ id, error: error.stack }); }
});
process.on('disconnect', () => { for (const item of held.values()) item.agent.destroy(); process.exit(); });
