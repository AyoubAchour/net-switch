// Test clients for the Linux spike. Copies of the Node binary run this file
// from different paths (/opt/nsapps/alpha/node, /opt/nsapps/bravo/node), so the
// engine sees different apps.
//
//   node client.mjs whoami --to 192.0.2.10:7003[,host:port...] --count N [--concurrency C] [--out file]
//   node client.mjs udp --to 192.0.2.10:7001 --count N [--sockets S] [--hold ms]
//   node client.mjs stream --to 192.0.2.10:7002 --seconds S [--interval ms] --log file
//   node client.mjs hold-files --count N
//   node client.mjs proxied --proxy 127.0.0.1:2080 --url http://127.0.0.1:8090/slow?ms=3000 [--wait-file path]
import { createSocket } from 'node:dgram';
import { appendFileSync, existsSync, openSync, writeFileSync } from 'node:fs';
import { connect } from 'node:net';
import { performance } from 'node:perf_hooks';
import { setTimeout as delay } from 'node:timers/promises';

const [mode, ...args] = process.argv.slice(2);
const option = (name, fallback) => {
  const index = args.indexOf(name);
  return index >= 0 ? args[index + 1] : fallback;
};
const endpoint = (text) => {
  const at = text.lastIndexOf(':');
  return { host: text.slice(0, at), port: Number(text.slice(at + 1)) };
};
const percentile = (values, p) => {
  if (values.length === 0) return null;
  const sorted = [...values].sort((a, b) => a - b);
  return Math.round(sorted[Math.min(sorted.length - 1, Math.floor((p / 100) * sorted.length))] * 10) / 10;
};
const tally = (items) => items.reduce((counts, item) => ((counts[item] = (counts[item] ?? 0) + 1), counts), {});

async function whoami() {
  const targets = option('--to').split(',').map(endpoint);
  const count = Number(option('--count', '100'));
  const concurrency = Number(option('--concurrency', '1'));
  const timeout = Number(option('--timeout', '8000'));
  const results = new Array(count);
  const one = (index) =>
    new Promise((resolve) => {
      const target = targets[index % targets.length];
      const started = performance.now();
      const result = { index, target: `${target.host}:${target.port}`, port: null, seen: null, error: null, ms: null, connectMs: null };
      let data = '';
      let done = false;
      const finish = () => {
        if (done) return;
        done = true;
        clearTimeout(timer);
        result.ms = Math.round((performance.now() - started) * 10) / 10;
        if (!result.error) {
          result.seen = data.trim() || null;
          if (!result.seen) result.error = 'EMPTY';
        }
        resolve(result);
      };
      const socket = connect({ host: target.host, port: target.port });
      const timer = setTimeout(() => {
        result.error = 'TIMEOUT';
        // A socket still in SYN_SENT has its port already.
        result.port ??= socket.localPort ?? null;
        result.connected = false;
        socket.destroy();
        finish();
      }, timeout);
      socket.setEncoding('utf8');
      socket.on('connect', () => {
        result.port = socket.localPort;
        result.connected = true;
        result.connectMs = Math.round((performance.now() - started) * 10) / 10;
      });
      socket.on('data', (chunk) => (data += chunk));
      socket.on('error', (error) => (result.error ??= error.code ?? error.message));
      socket.on('close', finish);
    });
  let next = 0;
  const started = performance.now();
  await Promise.all(
    Array.from({ length: Math.min(concurrency, count) }, async () => {
      while (next < count) {
        const index = next;
        next += 1;
        results[index] = await one(index);
      }
    }),
  );
  const wallMs = Math.round(performance.now() - started);
  const ok = results.filter((result) => !result.error);
  const summary = {
    count,
    concurrency,
    ok: ok.length,
    errors: tally(results.filter((result) => result.error).map((result) => result.error)),
    seen: tally(ok.map((result) => result.seen)),
    wallMs,
    p50: percentile(ok.map((result) => result.ms), 50),
    p95: percentile(ok.map((result) => result.ms), 95),
    max: percentile(ok.map((result) => result.ms), 100),
    connectP50: percentile(ok.map((result) => result.connectMs ?? 0), 50),
    // A lost SYN is sent again after 1 s, so these show dropped handshakes.
    over1s: ok.filter((result) => result.ms >= 1000).length,
    // Source ports the kernel handed out more than once in this run.
    reusedPorts: results.filter((result, index) => result.port && results.findIndex((other) => other.port === result.port) < index).length,
    // The worst connections: how long, whether the handshake finished, and
    // whether an earlier connection in this run had used the same port.
    stalls: results
      .filter((result) => result.error || result.ms >= 1000)
      .slice(0, 8)
      .map((result) => {
        const earlier = results.findIndex((other) => other.port && other.port === result.port);
        const reuse = earlier >= 0 && earlier < result.index ? `,reused-from-#${earlier}` : '';
        return `${result.error ?? 'ok'}@${Math.round(result.ms)}ms:#${result.index}:port${result.port ?? '?'}${result.connected ? '' : ',no-handshake'}${reuse}`;
      }),
  };
  const out = option('--out');
  if (out) writeFileSync(out, JSON.stringify({ summary, results }));
  console.log(JSON.stringify(summary));
}

async function udp() {
  const target = endpoint(option('--to'));
  const count = Number(option('--count', '20'));
  const sockets = Number(option('--sockets', '1'));
  const hold = Number(option('--hold', '0'));
  const seen = [];
  const localPorts = [];
  const all = [];
  for (let s = 0; s < sockets; s += 1) {
    const socket = createSocket('udp4');
    all.push(socket);
    socket.on('message', (message) => seen.push(String(message).split(' ')[0]));
    socket.on('error', () => {});
    for (let n = 0; n < count; n += 1) {
      await new Promise((resolve) => socket.send(`dgram-${s}-${n}`, target.port, target.host, () => resolve()));
      if (n === 0) localPorts.push(socket.address().port);
      await delay(20);
    }
  }
  const deadline = Date.now() + 3000;
  while (seen.length < count * sockets && Date.now() < deadline) await delay(50);
  await delay(hold);
  for (const socket of all) socket.close();
  console.log(JSON.stringify({ sent: count * sockets, received: seen.length, seen: tally(seen), localPorts }));
}

async function stream() {
  const target = endpoint(option('--to'));
  const seconds = Number(option('--seconds', '20'));
  const interval = Number(option('--interval', '250'));
  const log = option('--log');
  const write = (text) => appendFileSync(log, `${Date.now()} ${text}\n`);
  const socket = connect({ host: target.host, port: target.port });
  socket.setEncoding('utf8');
  let n = 0;
  let buffer = '';
  let open = false;
  socket.on('connect', () => {
    open = true;
    write(`connected ${socket.localPort}`);
  });
  socket.on('data', (chunk) => {
    buffer += chunk;
    for (let index = buffer.indexOf('\n'); index >= 0; index = buffer.indexOf('\n')) {
      write(buffer.slice(0, index));
      buffer = buffer.slice(index + 1);
    }
  });
  socket.on('error', (error) => write(`error ${error.code ?? error.message}`));
  socket.on('close', () => {
    open = false;
    write('closed');
  });
  const ticker = setInterval(() => {
    if (open) socket.write(`ping ${(n += 1)}\n`);
  }, interval);
  await delay(seconds * 1000);
  clearInterval(ticker);
  write('done');
  socket.destroy();
  process.exit(0);
}

async function holdFiles() {
  const count = Number(option('--count', '5000'));
  const fds = [];
  for (let i = 0; i < count; i += 1) fds.push(openSync('/dev/null', 'r'));
  console.log(`holding ${fds.length}`);
  setInterval(() => {}, 1 << 30);
}

async function proxied() {
  const proxy = endpoint(option('--proxy'));
  const url = new URL(option('--url'));
  const waitFile = option('--wait-file');
  if (waitFile) while (!existsSync(waitFile)) await delay(50);
  const socket = connect({ host: proxy.host, port: proxy.port });
  socket.setEncoding('utf8');
  let data = '';
  socket.on('connect', () => {
    console.log(`local-port ${socket.localPort}`);
    socket.write(`GET ${url.href} HTTP/1.1\r\nHost: ${url.host}\r\nConnection: close\r\n\r\n`);
  });
  socket.on('data', (chunk) => (data += chunk));
  socket.on('error', (error) => console.log(`error ${error.code ?? error.message}`));
  await new Promise((resolve) => socket.on('close', resolve));
  console.log(`answer ${data.split('\r\n')[0]} | ${data.trim().split('\n').pop()}`);
}

// Connects again and again from one fixed source port, as an app that binds
// its port would, each after the last one closed. --late adds one more try
// after that long.
async function reuse() {
  const target = endpoint(option('--to'));
  const localPort = Number(option('--local-port'));
  const count = Number(option('--count', '4'));
  const gap = Number(option('--gap', '1000'));
  const timeout = Number(option('--timeout', '5000'));
  const late = Number(option('--late', '0'));
  const once = () =>
    new Promise((resolve) => {
      const started = performance.now();
      const socket = connect({ host: target.host, port: target.port, localPort });
      let data = '';
      let done = false;
      const finish = (what) => {
        if (done) return;
        done = true;
        clearTimeout(timer);
        socket.destroy();
        resolve(`${what}@${Math.round(performance.now() - started)}ms`);
      };
      const timer = setTimeout(() => finish('TIMEOUT'), timeout);
      socket.setEncoding('utf8');
      socket.on('data', (chunk) => (data += chunk));
      socket.on('error', (error) => finish(error.code ?? error.message));
      socket.on('close', () => finish(data.trim() ? `ok:${data.trim()}` : 'EMPTY'));
    });
  const outcomes = [];
  for (let i = 0; i < count; i += 1) {
    outcomes.push(await once());
    await delay(gap);
  }
  if (late > 0) {
    await delay(late);
    outcomes.push(`after ${Math.round(late / 1000)} s: ${await once()}`);
  }
  console.log(JSON.stringify({ localPort, outcomes }));
}

const modes = { whoami, udp, stream, 'hold-files': holdFiles, proxied, reuse };
if (!modes[mode]) {
  console.error(`unknown mode ${mode}`);
  process.exit(2);
}
await modes[mode]();
