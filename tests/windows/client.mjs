import assert from 'node:assert/strict';
import { createHash, randomBytes } from 'node:crypto';
import { createSocket } from 'node:dgram';
import { Agent as HTTPAgent, request as httpRequest } from 'node:http';
import { Agent as HTTPSAgent, request as httpsRequest } from 'node:https';
import { connect, createServer } from 'node:net';
import { setTimeout as delay } from 'node:timers/promises';

if (!process.send) throw new Error('Use the Windows acceptance runner');
const held = new Map();
let serial = 0;
const publicTarget = { host: '1.1.1.1', port: 443, path: '/cdn-cgi/trace', tls: true };

async function requestOn(item) {
  const target = item.target;
  const nonce = item.nonce ?? randomBytes(12).toString('hex');
  return new Promise((resolve, reject) => {
    const request = target.tls ? httpsRequest : httpRequest;
    const req = request({ host: target.host, port: target.port ?? target.http, path: target.path ?? `/echo?nonce=${nonce}`,
      localAddress: target.source,
      servername: target.tls ? 'one.one.one.one' : undefined, agent: item.agent, signal: AbortSignal.timeout(8000) }, (res) => {
      const port = res.socket.localPort;
      let body = '';
      res.setEncoding('utf8'); res.on('data', (chunk) => { body += chunk; }); res.on('error', reject);
      res.on('end', () => {
        try {
          assert.equal(res.statusCode, 200, body);
          if (target.tls) assert.match(body, /(?:^|\n)ip=/); else assert.equal(JSON.parse(body).nonce, nonce);
          if (item.port) assert(req.reusedSocket && item.port === port, `Held connection ${item.id} was replaced`);
          item.port = port;
          resolve({ id: item.id, port, body, reused: req.reusedSocket });
        } catch (error) { reject(error); }
      });
    });
    req.on('error', reject); req.end();
  });
}

async function open({ count = 1, target = publicTarget }) {
  const results = [];
  for (let n = 0; n < count; n += 10) {
    results.push(...await Promise.all(Array.from({ length: Math.min(10, count - n) }, async () => {
      const Agent = target.tls ? HTTPSAgent : HTTPAgent;
      const item = { id: ++serial, target, agent: new Agent({ keepAlive: true, maxSockets: 1, maxFreeSockets: 1 }) };
      held.set(item.id, item);
      return requestOn(item);
    })));
  }
  return results;
}

async function udp({ target, size = 64, stun = false, localAddress }) {
  const v6 = target.host.includes(':');
  const socket = createSocket(v6 ? 'udp6' : 'udp4');
  const transaction = randomBytes(12);
  const packet = stun ? Buffer.alloc(20) : randomBytes(size);
  if (stun) { packet.writeUInt16BE(1, 0); packet.writeUInt32BE(0x2112a442, 4); transaction.copy(packet, 8); }
  try {
    return await new Promise((resolve, reject) => {
      const replies = [], mappings = [];
      let unsolicited = false;
      const result = () => ({ port: socket.address().port, sent: packet.length, replies, mappings, unsolicited });
      const timer = setTimeout(() => {
        if (stun && new Set(replies).size >= 2) finish(resolve, result());
        else finish(reject, new Error(`UDP baseline/echo failed: ${replies.length} replies, size=${size}`));
      }, 5000);
      const finish = (fn, value) => { clearTimeout(timer); fn(value); };
      socket.on('error', (error) => finish(reject, error));
      socket.on('message', (reply, peer) => {
        try {
          assert.equal(peer.address, target.host);
          if (stun && reply.subarray(0, 12).toString() === 'unsolicited:') {
            assert(reply.subarray(12).equals(transaction)); unsolicited = true;
          } else if (stun) {
            assert.equal(reply.length, 32); assert.equal(reply.readUInt16BE(0), 0x0101);
            assert(reply.subarray(8, 20).equals(transaction));
            const mappedPort = reply.readUInt16BE(26) ^ 0x2112;
            mappings.push({ server: peer.port, port: mappedPort });
            replies.push(peer.port);
          } else { assert(reply.equals(packet), 'UDP payload corrupted'); replies.push(peer.port); }
          if ((!stun && replies.length) || (stun && new Set(replies).size >= 2 && unsolicited)) {
            finish(resolve, result());
          }
        } catch (error) { finish(reject, error); }
      });
      socket.bind(0, localAddress ?? (v6 ? '::' : '0.0.0.0'), () => {
        for (const port of target.udp.slice(0, stun ? 2 : 1)) socket.send(packet, port, target.host);
      });
    });
  } finally { socket.close(); }
}

async function freePort() {
  return new Promise((resolve, reject) => {
    const server = createServer(); server.on('error', reject);
    server.listen(0, '0.0.0.0', () => { const port = server.address().port; server.close(() => resolve(port)); });
  });
}

async function reuse({ target, count = 1000, gap = 0, length = 0, reusePort }) {
  const port = reusePort ?? await freePort();
  const samples = [];
  for (let i = 0; i < count; i++) {
    const nonce = randomBytes(12).toString('hex');
    const started = performance.now();
    let result, bindRetries = 0;
    do {
      result = await new Promise((resolve) => {
        const start = performance.now();
        let connected = false, remoteClosedFirst = false, header = '', body = '', bytes = 0, gotHeader = false;
        const digest = createHash('sha256');
        const socket = connect({ host: target.host, port: target.http, localAddress: target.source, localPort: port, allowHalfOpen: true });
        const timer = setTimeout(() => finish('timeout'), length ? 30_000 : 2000);
        let done = false;
        function finish(outcome) {
          if (done) return; done = true; clearTimeout(timer); socket.destroy();
          resolve({ port, outcome, connected, remoteClosedFirst, ms: performance.now() - start, bytes, sha256: digest.digest('hex'), header, body });
        }
        socket.on('connect', () => {
          connected = true;
          const path = length ? `/bytes?length=${length}` : `/close?nonce=${nonce}`;
          socket.write(`GET ${path} HTTP/1.1\r\nHost: target\r\nConnection: close\r\n\r\n`);
      });
      socket.on('data', (data) => {
        if (!gotHeader) {
          const combined = Buffer.concat([Buffer.from(header, 'latin1'), data]);
          const separator = combined.indexOf('\r\n\r\n');
          if (separator === -1) { header = combined.toString('latin1'); return; }
          header = combined.subarray(0, separator).toString('latin1'); gotHeader = true;
          data = combined.subarray(separator + 4);
        }
        bytes += data.length; digest.update(data); if (!length) body += data;
      });
      socket.on('end', () => { remoteClosedFirst = true; socket.end(); });
      socket.on('close', () => finish(remoteClosedFirst ? 'closed' : 'closed-without-fin'));
      socket.on('error', (error) => finish(error.code ?? error.message));
      });
      if (result.outcome !== 'EADDRINUSE' || performance.now() - started >= 100) break;
      // Node's close event can precede Winsock processing the final ACK. No
      // SYN was sent on this failed bind. Never retry a connected TCP attempt.
      bindRetries++;
      await delay(1);
    } while (true);
    result.bindRetries = bindRetries;
    result.ms = performance.now() - started;
    samples.push(result);
    if (result.outcome !== 'closed') break;
    assert.match(result.header, /^HTTP\/1\.1 200/);
    if (!length) assert.equal(JSON.parse(result.body).nonce, nonce, 'Old or corrupt data entered a new connection');
    if (length) {
      const expected = createHash('sha256'); const block = Buffer.alloc(64 * 1024, 0x5a);
      for (let n = 0; n < length; n += block.length) expected.update(block.subarray(0, Math.min(block.length, length - n)));
      assert.equal(result.bytes, length); assert.equal(result.sha256, expected.digest('hex'), 'Large TCP payload corrupted');
    }
    if (gap) await delay(gap);
  }
  return samples;
}

async function rejectBurst({ target, count = 100 }) {
  return Promise.all(Array.from({ length: count }, () => new Promise((resolve) => {
    const started = performance.now(); let done = false;
    const socket = connect({ host: target.host, port: target.http });
    const timer = setTimeout(() => finish('timeout'), 1500);
    function finish(outcome) { if (done) return; done = true; clearTimeout(timer); socket.destroy(); resolve({ outcome, ms: performance.now() - started }); }
    socket.on('connect', () => finish('connected'));
    socket.on('error', (error) => finish(error.code ?? error.message));
  })));
}

async function udpReject({ target, count = 100 }) {
  return Promise.all(Array.from({ length: count }, () => new Promise((resolve) => {
    const socket = createSocket('udp4');
    const started = performance.now(); let done = false, sent = 0;
    const finish = (outcome) => { if (done) return; done = true; clearTimeout(timer); clearInterval(sender); socket.close(); resolve({ outcome, sent, ms: performance.now() - started }); };
    const timer = setTimeout(() => finish('timeout'), 1500);
    const sender = setInterval(() => { if (!done && sent) { sent++; socket.send(Buffer.alloc(64), (error) => { if (error) finish(error.code); }); } }, 25);
    socket.on('error', (error) => finish(error.code ?? error.message));
    socket.on('message', () => finish('reply'));
    socket.connect(target.udp[0], target.host, () => { sent++; socket.send(Buffer.alloc(64), (error) => { if (error) finish(error.code); }); });
  })));
}

process.on('message', async ({ id, command, ...args }) => {
  try {
    let result;
    if (command === 'open') result = await open(args);
    else if (command === 'refresh') result = await Promise.all(args.ids.map((key) => requestOn(held.get(key))));
    else if (command === 'udp') result = await udp(args);
    else if (command === 'reuse') result = await reuse(args);
    else if (command === 'reject') result = await rejectBurst(args);
    else if (command === 'udpReject') result = await udpReject(args);
    else if (command === 'close') { for (const item of held.values()) item.agent.destroy(); held.clear(); result = true; }
    else throw new Error(`Unknown command ${command}`);
    process.send({ id, result });
  } catch (error) { process.send({ id, error: error.stack }); }
});
process.on('disconnect', () => process.exit());
