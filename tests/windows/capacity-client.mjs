import assert from 'node:assert/strict';
import net from 'node:net';

assert(process.send, 'Use the hosted capacity runner');
const sockets = [];
let lost = 0;
process.on('message', async ({ id, command, host, ports, count }) => {
  try {
    if (command === 'open') {
      for (let n = 0; n < count; n += 32) {
        await Promise.all(Array.from({ length: Math.min(32, count - n) }, (_, k) => new Promise((resolve, reject) => {
          const socket = net.connect({ host, port: ports[(sockets.length + k) % ports.length] });
          const timeout = setTimeout(() => { socket.destroy(); reject(new Error('Capacity handshake/echo deadline')); }, 15_000);
          socket.once('error', (error) => { clearTimeout(timeout); reject(error); });
          socket.once('connect', () => socket.write(Buffer.from([0x71])));
          socket.once('data', (b) => {
            clearTimeout(timeout);
            if (b.length !== 1 || b[0] !== 0x71) { socket.destroy(); reject(new Error('Capacity payload mismatch')); return; }
            sockets.push(socket);
            socket.on('close', () => lost++);
            resolve();
          });
        })));
      }
      process.send({ id, result: { held: sockets.length, lost } });
    } else if (command === 'status') {
      process.send({ id, result: { held: sockets.length, lost, live: sockets.filter((s) => !s.destroyed).length } });
    } else if (command === 'close') {
      for (const socket of sockets) socket.destroy();
      process.send({ id, result: { closed: sockets.length } });
    } else throw new Error('Unknown capacity action');
  } catch (error) { process.send({ id, error: error.stack }); }
});
process.on('disconnect', () => { for (const socket of sockets) socket.destroy(); process.exit(0); });
