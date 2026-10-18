// The fake internet's servers for the Linux spike. Each one tells the client
// which address it saw, and each line's router hides its traffic behind its own
// address, so the answer names the line a connection used.
//
//   node server.mjs [--host 0.0.0.0] [--http-port 8080] [--http-only]
//
//   7003  whoami: writes the address it saw, then closes
//   7002  stream: answers each "ping N" line with "pong N <address>"
//   7001  UDP: answers each datagram with "<address> <datagram>"
//   8080  HTTP: the body is the address it saw; /slow?ms=N waits first
import { createSocket } from 'node:dgram';
import { createServer as createHttpServer } from 'node:http';
import { createServer } from 'node:net';

const args = process.argv.slice(2);
const option = (name, fallback) => {
  const index = args.indexOf(name);
  return index >= 0 ? args[index + 1] : fallback;
};
const host = option('--host', '0.0.0.0');
const httpPort = Number(option('--http-port', '8080'));
const httpOnly = args.includes('--http-only');
const plain = (address) => String(address ?? '').replace(/^::ffff:/, '');

const listening = [];
const listen = (server, port) =>
  listening.push(new Promise((resolve, reject) => server.once('error', reject).listen({ port, host, backlog: 4096 }, resolve)));

listen(
  createHttpServer((request, response) => {
    const url = new URL(request.url, 'http://spike');
    const wait = url.pathname === '/slow' ? Math.min(Number(url.searchParams.get('ms')) || 3000, 60_000) : 0;
    setTimeout(() => {
      response.writeHead(200, { 'Content-Type': 'text/plain', Connection: 'close' });
      response.end(`${plain(request.socket.remoteAddress)}\n`);
    }, wait);
  }),
  httpPort,
);

if (!httpOnly) {
  listen(
    createServer((socket) => {
      socket.on('error', () => {});
      socket.end(`${plain(socket.remoteAddress)}\n`);
    }),
    7003,
  );

  listen(
    createServer((socket) => {
      socket.on('error', () => {});
      let buffer = '';
      socket.on('data', (chunk) => {
        buffer += chunk;
        for (let index = buffer.indexOf('\n'); index >= 0; index = buffer.indexOf('\n')) {
          const line = buffer.slice(0, index);
          buffer = buffer.slice(index + 1);
          socket.write(`pong ${line.replace(/^ping /, '')} ${plain(socket.remoteAddress)}\n`);
        }
      });
    }),
    7002,
  );

  const udp = createSocket('udp4');
  udp.on('message', (message, remote) => udp.send(`${remote.address} ${message}`, remote.port, remote.address));
  listening.push(new Promise((resolve) => udp.bind(7001, host === '0.0.0.0' ? undefined : host, resolve)));
}

await Promise.all(listening);
console.log(`servers ready on ${host}`);
