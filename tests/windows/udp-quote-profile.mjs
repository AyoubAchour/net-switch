import assert from 'node:assert/strict';
import { createWriteStream } from 'node:fs';
import { mkdir, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { launchOptions, recordLaunch, startServer } from './launch.mjs';
import { targets } from './targets.mjs';
import { udpIdentity } from './udp-identity.mjs';
import { hostedOnly, startHarness } from './testisp/harness.mjs';

hostedOnly();
const options = launchOptions();
assert.equal(options.profile, 'v1');
const directory = path.resolve('dist/windows-udp-quote');
await mkdir(directory, { recursive: true });
const log = createWriteStream(path.join(directory, 'server-output.log'));
const result = { architecture: process.arch, complete: false, acceptanceSuite: false };
let harness, responder, server;
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
} finally {
  if (server) await server.quit().catch((error) => { result.quitError = error.stack; process.exitCode = 1; });
  if (responder) await responder.close();
  if (harness) await harness.close().catch((error) => { result.cleanupError = error.stack; process.exitCode = 1; });
  await writeFile(path.join(directory, 'report.json'), JSON.stringify(result, null, 2));
  log.end();
}
