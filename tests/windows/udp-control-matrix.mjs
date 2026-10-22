// The UDP option matrix (SYSTEM-DESIGN 5.9 open question). Starts TestISP so
// the controls bind at the gate's own address, then runs each engine-half
// variant of TestUDPControlVariant in its own test process, with a pause
// between processes, in two rounds (the second in reverse order) so run order
// cannot skew the rates. No engine and no TUN are involved.
import assert from 'node:assert/strict';
import { mkdir } from 'node:fs/promises';
import path from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import { hostedOnly, run, startHarness } from './testisp/harness.mjs';

hostedOnly();
const variants = ['go', 'raw', 'raw+broadcast', 'raw+unicastif', 'raw+resetsoff', 'raw+fionbio', 'raw+iocp',
  'raw+protocol17', 'all', 'all+protocol17', 'golike', 'production', 'production+watch'];
const cycles = Number(process.env.NETSWITCH_UDP_RECOVERY_CYCLES ?? 10);
const pauseMs = 20_000;
const directory = path.resolve('dist/windows-udp-matrix');
await mkdir(directory, { recursive: true });
const harness = await startHarness(path.join(directory, 'testisp'));
const totals = {};
try {
  for (const order of [variants, [...variants].reverse()]) {
    for (const variant of order) {
      await delay(pauseMs);
      const result = await run(path.resolve('dist/windows-test/windows-platform.test.exe'),
        ['-test.v', '-test.run=^TestUDPControlVariant$', '-test.timeout=15m'],
        { env: { NETSWITCH_PORT_GATE: '1', NETSWITCH_UDP_RECOVERY_CYCLES: String(cycles), NETSWITCH_UDP_CONTROL_VARIANT: variant,
          NETSWITCH_UDP_BASELINE_SOURCE: harness.testisp.address, NETSWITCH_UDP_BASELINE_INDEX: String(harness.testisp.index) },
        timeout: 900_000 });
      const pick = (marker) => result.stdout.split(/\r?\n/).filter((line) => line.includes(marker))
        .map((line) => JSON.parse(line.slice(line.indexOf(marker) + marker.length)))[0];
      const cyclesLine = pick('WINDOWS NATIVE UDP RECOVERY CYCLES ');
      const variantLine = pick('WINDOWS UDP CONTROL VARIANT ');
      assert(cyclesLine && variantLine, `variant ${variant} did not report: ${result.stdout.slice(-2000)}`);
      const bursts = cyclesLine.cycles.filter((cycle) => cycle.reopenRefused > 0).length;
      const restoreRefused = cyclesLine.cycles.reduce((n, cycle) => n + cycle.restoreRefused, 0);
      const codes = {};
      for (const refusal of cyclesLine.cycles.flatMap((cycle) => cycle.refusals ?? [])) {
        const key = `${refusal.phase}/${refusal.half}/${refusal.code}`;
        codes[key] = (codes[key] ?? 0) + 1;
      }
      const row = { variant, socket: variantLine.socket, provider: variantLine.provider, heldPairs: variantLine.heldPairs,
        attempts: cyclesLine.reopenAttempts, refused: cyclesLine.reopenRefused, burstCycles: bursts, restoreRefused, codes };
      console.log(`WINDOWS UDP CONTROL RUN ${JSON.stringify(row)}`);
      const total = totals[variant] ??= { variant, socket: row.socket, provider: row.provider, runs: 0, attempts: 0, refused: 0, burstCycles: 0, restoreRefused: 0, heldPairs: [] };
      total.runs++; total.attempts += row.attempts; total.refused += row.refused; total.burstCycles += bursts;
      total.restoreRefused += restoreRefused; total.heldPairs.push(row.heldPairs);
    }
  }
  for (const total of Object.values(totals)) console.log(`WINDOWS UDP CONTROL MATRIX ${JSON.stringify(total)}`);
} finally {
  await harness.close();
}
