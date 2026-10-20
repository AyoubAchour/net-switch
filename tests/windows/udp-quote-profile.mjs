import assert from 'node:assert/strict';
import { createWriteStream } from 'node:fs';
import { mkdir, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { launchOptions, recordLaunch, startServer } from './launch.mjs';
import { targets } from './targets.mjs';
import { udpIdentity } from './udp-identity.mjs';
import { hostedOnly, run, startHarness } from './testisp/harness.mjs';

hostedOnly();
const options = launchOptions();
assert.equal(options.profile, 'v1');
const directory = path.resolve('dist/windows-udp-quote');
await mkdir(directory, { recursive: true });
const log = createWriteStream(path.join(directory, 'server-output.log'));
const result = { architecture: process.arch, complete: false, acceptanceSuite: false };
let harness, responder, server, traceStarted = false, captureSince, lines;
try {
  result.executables = await recordLaunch(options);
  harness = await startHarness(path.join(directory, 'testisp'));
  responder = await targets(harness.uplink.address);
  await harness.control('targets', { ports: [responder.direct.http, ...responder.direct.udp] });
  const data = path.join(directory, 'app');
  await mkdir(data, { recursive: true });
  await writeFile(path.join(data, 'settings.json'), JSON.stringify({ checkForUpdates: false }));
  server = await startServer(options, data, (chunk) => log.write(chunk));
  const initial = await server.on();
  const main = initial.lines[0];
  assert.equal(main.alias, harness.uplink.alias);
  await server.api('lines/add', { alias: 'TestISP' });
  const second = (await server.on()).lines.find((line) => line.alias === 'TestISP');
  assert(second);
  lines = { main, second };
  await run('auditpol.exe', ['/set', '/subcategory:Filtering Platform Packet Drop', '/success:enable', '/failure:enable']);
  captureSince = new Date().toISOString();
  await run('netsh.exe', ['trace', 'start', 'scenario=InternetClient', 'capture=no', 'report=no',
    'persistent=no', 'correlation=no', 'maxsize=16', `tracefile=${path.join(directory, 'udp-network.etl')}`]);
  traceStarted = true;
  // Run the exact acceptance case, including its old-socket positive control,
  // one-second invalidation bound and real SIO_UDP_CONNRESET refusal assertion.
  result.reuse = await udpIdentity({ server, responder, directory, main, second, blocked: true });
  assert(result.reuse.first.source.startsWith('198.18.0.1:'), 'Positive control bypassed the app TUN');
  result.stats = await server.api('engine-command', { method: 'stats' });
  const stats = result.stats.engine;
  const records = stats.packetTrace?.records;
  assert(records?.length, 'Missing real Wintun boundary capture');
  const incoming = records.filter((record) => record.direction === 'from-app')
    .map((record) => Buffer.from(record.header, 'hex')).filter((packet) => packet[9] === 17);
  const refusals = records.filter((record) => {
    const packet = Buffer.from(record.header, 'hex');
    const off = (packet[0] & 15) * 4;
    return record.direction === 'to-app' && packet[9] === 1 && packet[off] === 3 && packet[off + 1] === 3;
  });
  assert(refusals.length > 0, 'No port-unreachable crossed the Wintun write boundary');
  for (const record of refusals) {
    assert(!record.error && record.batchWritten === record.batchPackets, JSON.stringify(record));
    const packet = Buffer.from(record.header, 'hex');
    const off = (packet[0] & 15) * 4;
    const quote = packet.subarray(off + 8);
    assert(incoming.some((original) => original.subarray(0, quote.length).equals(quote)),
      `ICMP quotation differs from every triggering UDP header: ${quote.toString('hex')}`);
  }
  result.summary = {
    receivedUDPHeaders: incoming.length, writtenICMPRefusals: refusals.length,
    socketRefusals: result.reuse.next.events.filter((event) => event.outcome === 'refused').length,
    socketTimeouts: result.reuse.next.events.filter((event) => event.outcome === 'timeout').length,
    allQuotesMatch: true, tunDropped: stats.tunDropped, wintun: stats.wintun,
    droppedNotices: stats.flows?.DroppedNotices,
  };
  result.complete = true;
  console.log(`WINDOWS UDP QUOTE ${JSON.stringify(result.summary)}`);
} catch (error) {
  result.error = error.stack;
  result.evidence = error.evidence;
  if (server) result.stats = await server.api('engine-command', { method: 'stats' }).catch(String);
  console.error(error);
  console.error(`WINDOWS UDP QUOTE FAILURE ${JSON.stringify(result)}`);
  process.exitCode = 1;
  // ETW proved STATUS_FWP_DROP_NOICMP after a successful Wintun write. This
  // isolated A/B rule diagnoses filtering; it cannot turn the original case
  // green and is never installed by production or full acceptance.
  if (lines && error.message.includes('never received an ICMP refusal')) {
    const name = 'NetSwitch-Quote-Diagnostic';
    try {
      await run('netsh.exe', ['advfirewall', 'firewall', 'add', 'rule', `name=${name}`, 'dir=in',
        'action=allow', 'protocol=icmpv4:3,3', 'localip=198.18.0.1', 'remoteip=198.19.128.2', 'profile=any']);
      result.allowRuleDiagnostic = await udpIdentity({ server, responder, directory, ...lines, blocked: true })
        .then((value) => ({ passed: true, refusals: value.next.events.filter((event) => event.outcome === 'refused').length }))
        .catch((error) => ({ passed: false, error: error.stack }));
      console.log(`WINDOWS UDP ALLOW-RULE DIAGNOSTIC ${JSON.stringify(result.allowRuleDiagnostic)}`);
    } finally {
      await run('netsh.exe', ['advfirewall', 'firewall', 'delete', 'rule', `name=${name}`]);
    }
  }
} finally {
  if (traceStarted) {
    await run('netsh.exe', ['trace', 'stop'], { timeout: 120_000 }).catch((error) => { result.traceError = error.message; });
    await run('netsh.exe', ['trace', 'convert', `input=${path.join(directory, 'udp-network.etl')}`,
      `output=${path.join(directory, 'udp-network.txt')}`, 'dump=TXT', 'report=no', 'overwrite=yes'],
    { timeout: 120_000 }).catch((error) => { result.traceConvertError = error.message; });
    const events = await run('powershell.exe', ['-NoProfile', '-File', path.resolve('tests/windows/udp-drop-events.ps1')],
      { env: { NETSWITCH_UDP_CAPTURE_SINCE: captureSince } }).catch((error) => ({ stdout: JSON.stringify({ error: error.message }) }));
    result.firewallDrops = JSON.parse(events.stdout || '[]');
    console.log(`WINDOWS UDP FIREWALL EVENTS ${JSON.stringify(result.firewallDrops)}`);
    await run('netsh.exe', ['wfp', 'show', 'state', `file=${path.join(directory, 'wfp-state.xml')}`])
      .catch((error) => { result.firewallStateError = error.message; });
  }
  if (server) await server.quit().catch((error) => { result.quitError = error.stack; process.exitCode = 1; });
  if (responder) await responder.close();
  if (harness) await harness.close().catch((error) => { result.cleanupError = error.stack; process.exitCode = 1; });
  await writeFile(path.join(directory, 'report.json'), JSON.stringify(result, null, 2));
  log.end();
}
