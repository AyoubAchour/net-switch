import assert from 'node:assert/strict';
import { createSocket } from 'node:dgram';
import { once } from 'node:events';
import test from 'node:test';
import { udpProbe } from '../scripts/tun-test-dns.mjs';

async function responder(t, handle) {
  const socket = createSocket('udp4');
  socket.bind(0, '127.0.0.1');
  await once(socket, 'listening');
  t.after(() => new Promise((resolve) => socket.close(resolve)));
  socket.on('message', (query, peer) => handle(query, (reply) => socket.send(reply, peer.port, peer.address)));
  return { server: '127.0.0.1', port: socket.address().port };
}
function negativeAnswer(query) {
  const reply = Buffer.from(query.subarray(0, 35));
  reply.writeUInt16BE(0x8183, 2); // Response, recursion available, NXDOMAIN.
  reply.writeUInt16BE(0, 10); // No OPT record in the response.
  return reply;
}
for (const size of [64, 1800]) {
  test(`runner DNS sends one ${size}-byte packet with a complete padded question`, async (t) => {
    let received = 0;
    const endpoint = await responder(t, (query, send) => {
      received++;
      assert.equal(query.length, size);
      assert.equal(query.readUInt16BE(4), 1);
      assert.equal(query.readUInt16BE(10), 1);
      assert.equal(query.subarray(12, 35).toString('hex'), '096e657473776974636807696e76616c69640000010001');
      assert.equal(query.readUInt16BE(36), 41);
      assert.equal(query.readUInt16BE(46), 12);
      assert.equal(query.readUInt16BE(48), size - 50);
      send(negativeAnswer(query));
    });
    const result = await udpProbe({ size, ...endpoint });
    assert.equal(received, 1);
    assert.equal(result.sent, size);
    assert.equal(result.received, 35);
    assert(result.port > 0);
  });
}
test('runner DNS rejects a response for the wrong question', async (t) => {
  const endpoint = await responder(t, (query, send) => {
    const reply = negativeAnswer(query);
    reply[13] ^= 1;
    send(reply);
  });
  await assert.rejects(udpProbe({ size: 64, ...endpoint }), /DNS question changed/);
});
test('runner DNS rejects SERVFAIL instead of accepting any DNS reply', async (t) => {
  const endpoint = await responder(t, (query, send) => {
    const reply = negativeAnswer(query);
    reply[3] = 0x82;
    send(reply);
  });
  await assert.rejects(udpProbe({ size: 64, ...endpoint }), /must return NXDOMAIN/);
});
test('runner DNS does not retry when only an unrelated transaction replies', async (t) => {
  let received = 0;
  const endpoint = await responder(t, (query, send) => {
    received++;
    const reply = negativeAnswer(query);
    reply[0] ^= 1;
    send(reply);
  });
  await assert.rejects(udpProbe({ size: 64, ...endpoint, timeoutMs: 200 }), /did not answer 64 UDP bytes/);
  assert.equal(received, 1);
});
