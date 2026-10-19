import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { createSocket } from 'node:dgram';

// Ask the harness's local responder for a reserved .invalid name. The answer
// is NXDOMAIN, so neither a public resolver nor a public domain is a dependency.
// EDNS padding preserves the 64- and 1800-byte UDP coverage.
export async function udpProbe({ size, server, port = 53, timeoutMs = 5000 }) {
  const socket = createSocket('udp4');
  const question = Buffer.from('096e657473776974636807696e76616c69640000010001', 'hex');
  const header = Buffer.from('000001000001000000000001', 'hex');
  randomBytes(2).copy(header);
  const padding = Math.max(0, size - header.length - question.length - 15);
  const opt = Buffer.alloc(15 + padding);
  opt.writeUInt16BE(41, 1); opt.writeUInt16BE(4096, 3);
  opt.writeUInt16BE(4 + padding, 9); opt.writeUInt16BE(12, 11); opt.writeUInt16BE(padding, 13);
  const packet = Buffer.concat([header, question, opt]);
  try {
    return await new Promise((resolve, reject) => {
      let done = false;
      const timer = setTimeout(() => finish(reject,
        new Error(`Test DNS ${server}:${port} did not answer ${packet.length} UDP bytes`)), timeoutMs);
      const finish = (fn, value) => { if (done) return; done = true; clearTimeout(timer); fn(value); };
      socket.on('error', (error) => finish(reject, error));
      socket.on('message', (reply, peer) => {
        if (peer.address !== server || peer.port !== port || reply.length < 12 || reply.readUInt16BE(0) !== header.readUInt16BE(0)) return;
        try {
          assert(reply[2] & 0x80, 'DNS response flag missing');
          assert.equal(reply[2] & 0x02, 0, 'Truncated DNS response');
          assert.equal(reply.readUInt16BE(4), 1, 'DNS question count');
          assert.deepEqual(reply.subarray(12, 12 + question.length), question, 'DNS question changed');
          assert.equal(reply[3] & 15, 3, 'Reserved .invalid name must return NXDOMAIN');
          finish(resolve, { server, sent: packet.length, received: reply.length, port: socket.address().port });
        } catch (error) { finish(reject, error); }
      });
      socket.send(packet, port, server, (error) => { if (error) finish(reject, error); });
    });
  } finally { socket.close(); }
}
