import { createServer } from 'node:http';
import { createSocket } from 'node:dgram';
import { once } from 'node:events';
import { hostedOnly } from './testisp/harness.mjs';

// Both addresses reach this responder: the real NIC's address directly, and a
// documentation-range destination translated by TestISP after crossing its TUN.
export async function targets(address) {
  hostedOnly();
  const seen = [];
  const server = createServer(async (req, res) => {
    const url = new URL(req.url, 'http://target');
    const observation = { source: req.socket.remoteAddress, port: req.socket.remotePort,
      nonce: url.searchParams.get('nonce'), path: url.pathname };
    seen.push(observation);
    if (url.pathname === '/close') res.setHeader('Connection', 'close');
    if (url.pathname === '/bytes') {
      const length = Math.min(100_000_000, Math.max(0, Number(url.searchParams.get('length')) || 0));
      res.writeHead(200, { 'Content-Type': 'application/octet-stream', 'Content-Length': length, Connection: 'close' });
      const block = Buffer.alloc(64 * 1024, 0x5a);
      for (let sent = 0; sent < length; sent += block.length) {
        if (!res.write(block.subarray(0, Math.min(block.length, length - sent)))) {
          await new Promise((resolve) => {
            const done = () => { res.off('drain', done); res.off('close', done); resolve(); };
            res.once('drain', done); res.once('close', done);
          });
          if (res.destroyed) return;
        }
      }
      res.end();
      return;
    }
    res.setHeader('Content-Type', 'application/json');
    res.end(JSON.stringify(observation));
  });
  server.keepAliveTimeout = 180_000;
  server.headersTimeout = 185_000;
  server.listen(0, address);
  await once(server, 'listening');
  const udp = [];
  for (let i = 0; i < 3; i++) {
    const socket = createSocket('udp4');
    socket.bind(0, address);
    await once(socket, 'listening');
    socket.on('error', (error) => { console.error('target UDP error', error); });
    socket.on('message', (packet, peer) => {
      seen.push({ protocol: 'udp', target: i, source: peer.address, port: peer.port, bytes: packet.length });
      // The legacy TUN test's padded example.com query gets a deterministic A
      // answer, retaining EDNS padding so large replies exercise reassembly too.
      if (packet.length >= 44 && packet.readUInt16BE(0) === 0x1234 && packet.readUInt16BE(2) === 0x0100 && packet.readUInt16BE(4) === 1) {
        const header = Buffer.from(packet.subarray(0, 12)); header.writeUInt16BE(0x8180, 2); header.writeUInt16BE(1, 6);
        const answer = Buffer.from('c00c000100010000003c0004cb007107', 'hex');
        socket.send(Buffer.concat([header, packet.subarray(12, 29), answer, packet.subarray(29)]), peer.port, peer.address);
      // STUN Binding response with XOR-MAPPED-ADDRESS (RFC 8489).
      } else if (packet.length >= 20 && packet.readUInt16BE(0) === 1 && packet.readUInt32BE(4) === 0x2112a442) {
        const response = Buffer.alloc(32);
        response.writeUInt16BE(0x0101, 0); response.writeUInt16BE(12, 2);
        packet.copy(response, 4, 4, 20);
        response.writeUInt16BE(0x0020, 20); response.writeUInt16BE(8, 22);
        response[25] = 1; response.writeUInt16BE(peer.port ^ 0x2112, 26);
        const ip = peer.address.split('.').map(Number);
        const cookie = [0x21, 0x12, 0xa4, 0x42];
        for (let n = 0; n < 4; n++) response[28 + n] = ip[n] ^ cookie[n];
        socket.send(response, peer.port, peer.address);
        if (i === 1) udp[2].send(Buffer.concat([Buffer.from('unsolicited:'), packet.subarray(8, 20)]), peer.port, peer.address, (error) => {
          seen.push({ protocol: 'udp-unsolicited', from: udp[2].address().port, to: peer.port, error: error?.message ?? null });
        });
      } else socket.send(packet, peer.port, peer.address);
    });
    udp.push(socket);
  }
  return {
    direct: { host: address, http: server.address().port, udp: udp.map((socket) => socket.address().port) },
    virtual: { host: '198.19.128.2', http: server.address().port, udp: udp.map((socket) => socket.address().port) },
    seen,
    async close() { server.closeAllConnections(); await new Promise((resolve) => server.close(resolve)); for (const socket of udp) socket.close(); },
  };
}
