// Turns raw spike output into short result lines.
//
//   node analyze.mjs conns [--dest-ip IP] [--dest-port P] < clash-api-connections.json
//   node analyze.mjs combine --file whoami.json --share-b 0.3333
//   node analyze.mjs stream --log file --start ms --ready ms --stop ms
//   node analyze.mjs iperf --file iperf.json
import { readFileSync } from 'node:fs';
import { FIRST_SHARED_PORT, lineForPort } from '../../lib/lines.mjs';

const [mode, ...args] = process.argv.slice(2);
const option = (name, fallback) => {
  const index = args.indexOf(name);
  return index >= 0 ? args[index + 1] : fallback;
};
const LINE_BY_ADDRESS = { '192.0.2.1': 'A', '192.0.2.2': 'B' };

function conns() {
  const body = JSON.parse(readFileSync(0, 'utf8') || '{}');
  const ip = option('--dest-ip');
  const port = option('--dest-port');
  const list = (body.connections ?? []).filter(
    ({ metadata }) => (!ip || metadata.destinationIP === ip) && (!port || metadata.destinationPort === port),
  );
  for (const { metadata, chains, rule } of list) {
    console.log(
      `${metadata.network} ${metadata.sourceIP}:${metadata.sourcePort} -> ${metadata.destinationIP}:${metadata.destinationPort}` +
        ` processPath=${JSON.stringify(metadata.processPath)} chains=${JSON.stringify(chains)} rule=${JSON.stringify(rule)}`,
    );
  }
  if (list.length === 0) console.log('(no matching connections)');
}

function combine() {
  const { summary, results } = JSON.parse(readFileSync(option('--file'), 'utf8'));
  const shareB = Number(option('--share-b'));
  const shares = [
    ['A', 1 - shareB],
    ['B', shareB],
  ];
  const ok = results.filter((result) => !result.error);
  const lines = ok.map((result) => LINE_BY_ADDRESS[result.seen] ?? result.seen);
  const count = (line) => lines.filter((value) => value === line).length;
  const expectedB = Math.round(summary.count * shareB);
  const predicted = ok.filter((result) => result.port >= FIRST_SHARED_PORT);
  const agree = predicted.filter((result) => lineForPort(result.port, shares) === LINE_BY_ADDRESS[result.seen]).length;
  const ports = results.map((result) => result.port).filter(Number.isInteger);
  const even = ports.filter((port) => port % 2 === 0).length;
  const deltas = {};
  for (let i = 1; i < ports.length; i += 1) {
    const delta = ports[i] - ports[i - 1];
    deltas[delta] = (deltas[delta] ?? 0) + 1;
  }
  const topDeltas = Object.entries(deltas)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 6)
    .map(([delta, n]) => `${delta}:${n}`)
    .join(' ');
  const verdict = Math.abs(count('B') - expectedB) <= 25 ? 'PASS' : 'FAIL';
  console.log(
    `${verdict} A=${count('A')} B=${count('B')} (target ${summary.count - expectedB}/${expectedB} ±25) errors=${JSON.stringify(summary.errors)}` +
      ` | rule agreement ${agree}/${predicted.length} | ports even=${even} odd=${ports.length - even}` +
      ` range ${Math.min(...ports)}-${Math.max(...ports)} | top deltas ${topDeltas}`,
  );
  console.log(`first ports: ${ports.slice(0, 24).join(' ')}`);
}

function stream() {
  const start = Number(option('--start'));
  const ready = Number(option('--ready'));
  const stop = Number(option('--stop', `${Number.MAX_SAFE_INTEGER}`));
  const events = readFileSync(option('--log'), 'utf8')
    .split('\n')
    .filter(Boolean)
    .map((line) => {
      const [ts, kind, ...rest] = line.split(' ');
      return { ts: Number(ts), kind, rest };
    });
  const phase = (ts) => (ts < start ? 'before' : ts < ready ? 'starting' : ts < stop ? 'running' : 'after');
  const pongs = { before: [], starting: [], running: [], after: [] };
  const notes = [];
  let last = null;
  let longestGap = 0;
  for (const event of events) {
    if (event.kind === 'pong') {
      pongs[phase(event.ts)].push(LINE_BY_ADDRESS[event.rest[1]] ?? event.rest[1]);
      if (last !== null && event.ts >= start) longestGap = Math.max(longestGap, event.ts - last);
      last = event.ts;
    } else if (event.kind !== 'done') {
      notes.push(`${event.kind}${event.rest.length ? ` ${event.rest.join(' ')}` : ''} at ${((event.ts - ready) / 1000).toFixed(1)}s`);
    }
  }
  const describe = (list) => `${list.length}${list.length ? ` via ${[...new Set(list)].join('+')}` : ''}`;
  const lastPong = last === null ? 'never' : `${((last - ready) / 1000).toFixed(1)}s`;
  const survived = pongs.running.length > 0 && last !== null && last >= stop - 1500;
  console.log(
    `${survived ? 'SURVIVED' : 'BROKEN'} pongs before=${describe(pongs.before)} starting=${describe(pongs.starting)}` +
      ` running=${describe(pongs.running)} after-stop=${describe(pongs.after)} | last pong ${lastPong} after ready` +
      ` | longest gap ${(longestGap / 1000).toFixed(1)}s | events: ${notes.join('; ') || 'none'}`,
  );
}

function iperf() {
  let body;
  try {
    body = JSON.parse(readFileSync(option('--file'), 'utf8'));
  } catch (error) {
    console.log(`error unreadable iperf3 output (${error.message})`);
    return;
  }
  if (body.error) {
    console.log(`error ${body.error}`);
    return;
  }
  const received = body.end?.sum_received ?? {};
  const gbps = ((received.bits_per_second ?? 0) / 1e9).toFixed(2);
  const gbytes = ((received.bytes ?? 0) / 1e9).toFixed(2);
  console.log(`${gbps} Gbit/s ${gbytes} GB retransmits=${body.end?.sum_sent?.retransmits ?? '?'}`);
}

const modes = { conns, combine, stream, iperf };
if (!modes[mode]) {
  console.error(`unknown mode ${mode}`);
  process.exit(2);
}
modes[mode]();
