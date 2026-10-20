import assert from 'node:assert/strict';
import { fork } from 'node:child_process';
import { mkdir, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { targets } from '../targets.mjs';
import { hostedOnly, run, startHarness } from './harness.mjs';

hostedOnly();
const dir = path.resolve('dist/testisp-reproduction');
await mkdir(dir, { recursive: true });
let harness, responder, worker, capturing = false;
const report = { architecture: process.arch, commit: process.env.GITHUB_SHA, requested: 10000, count: 0, slow: 0, failed: 0, rounds: [] };
try {
  harness = await startHarness(path.join(dir, 'gateway'));
  assert.equal(harness.testisp.tcpReuseHook, true);
  await harness.network('reuse-route');
  responder = await targets(harness.uplink.address);
  await harness.control('targets', { ports: [responder.virtual.http] });
  report.windowsSettings = (await run('powershell.exe', ['-NoProfile', '-Command',
    'Get-NetTCPSetting | Select-Object * | ConvertTo-Json -Depth 3 -Compress'])).stdout;
  if (process.env.TESTISP_PACKET_CAPTURE === 'true') {
    report.packetComponents = (await run('pktmon.exe', ['list'])).stdout;
    await run('pktmon.exe', ['filter', 'add', 'TestISPReuse', '-i', responder.virtual.host, '-t', 'TCP']);
    await run('pktmon.exe', ['start', '--capture', '--pkt-size', '128', '--flags', '0x01f', '--file-size', '128',
      '--file-name', path.join(dir, 'packets.etl'), '--log-mode', 'circular']);
    capturing = true;
  }
  worker = fork(path.resolve('tests/windows/client.mjs'), [], { windowsHide: true });
  let serial = 0;
  const client = (command, args = {}) => new Promise((resolve, reject) => {
    const id = ++serial;
    const timer = setTimeout(() => done(new Error('Reproduction client deadline')), 180000);
    const onMessage = (message) => { if (message.id === id) done(message.error && new Error(message.error), message.result); };
    const onExit = (code) => done(new Error(`Client exited ${code}`));
    function done(error, result) { clearTimeout(timer); worker.off('message', onMessage); worker.off('exit', onExit); error ? reject(error) : resolve(result); }
    worker.on('message', onMessage); worker.once('exit', onExit); worker.send({ id, command, ...args });
  });
  // Ten measured rounds, never a retry. A slow attempt is retained before the
  // next connection starts. The final status includes every recorded failure.
  for (let round = 1; round <= 10; round++) {
    const before = await harness.control('diagnostics');
    const samples = await client('reuse', { target: { ...responder.virtual, source: harness.testisp.address }, count: 1000,
      warmup: true, maxMs: 100, diagnostics: harness.diagnosticClient, continueAfterSlow: true });
    const after = await harness.control('diagnostics');
    const slow = samples.filter((s) => s.ms >= 100);
    const failed = samples.filter((s) => s.outcome !== 'closed');
    const summary = { round, count: samples.length, slow: slow.length, failed: failed.length, maxMs: Math.max(...samples.map((s) => s.ms)) };
    report.rounds.push(summary);
    report.count += summary.count;
    report.slow += summary.slow;
    report.failed += summary.failed;
    await writeFile(path.join(dir, `round-${round}.json`), JSON.stringify({ ...summary, before, after, samples, heartbeat: await client('heartbeat') }));
    console.log(`REUSE ROUND ${JSON.stringify(summary)}`);
    assert.equal(samples.length, 1000, 'Incomplete round; no retry');
    assert.equal(new Set(samples.map((s) => `${s.port}:${s.peerPort}`)).size, 1, 'Tuple changed within round');
    if (failed.length) break;
  }
  console.log(`REUSE TOTAL ${JSON.stringify(report)}`);
  if (report.count !== report.requested || report.slow || report.failed) process.exitCode = 1;
} catch (error) { report.error = error.stack; console.error(error); process.exitCode = 1; }
finally {
  if (capturing) {
    try {
      report.packetCounters = (await run('pktmon.exe', ['counters'])).stdout;
      report.packetStop = (await run('pktmon.exe', ['stop'])).stdout;
      await run('pktmon.exe', ['etl2txt', path.join(dir, 'packets.etl'), '--out', path.join(dir, 'packets.txt'), '--verbose', '3', '--hex'], { timeout: 120000 });
    } catch (error) { report.packetError = error.stack; process.exitCode = 1; }
  }
  if (worker?.connected) worker.disconnect();
  if (responder) await responder.close();
  if (harness) try { await harness.close(); } catch (error) { report.cleanupError = error.stack; process.exitCode = 1; }
  await writeFile(path.join(dir, 'report.json'), JSON.stringify(report, null, 2));
}
