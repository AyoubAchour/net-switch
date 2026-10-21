import assert from 'node:assert/strict';
import { createWriteStream } from 'node:fs';
import { mkdir, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { capacity } from './capacity.mjs';
import { launchOptions, recordLaunch, startServer } from './launch.mjs';
import { hostedOnly, run, startHarness } from './testisp/harness.mjs';

hostedOnly();
const options = launchOptions();
assert.equal(options.profile, 'v1');
const directory = path.resolve('dist/windows-capacity');
await mkdir(directory, { recursive: true });
const log = createWriteStream(path.join(directory, 'server-output.log'));
const result = { architecture: process.arch, complete: false, acceptanceSuite: false };
let harness, server;
const targetNetwork = (action) => run('powershell.exe', ['-NoProfile', '-ExecutionPolicy', 'Bypass',
  '-File', path.resolve('tests/windows/target-network.ps1'), '-Action', action],
{ env: { ACCEPTANCE_UPLINK: String(harness.uplink.index), ACCEPTANCE_TESTISP: String(harness.testisp.index) } });
try {
  result.executables = await recordLaunch(options);
  harness = await startHarness(path.join(directory, 'testisp'));
  await targetNetwork('capacity-ipv6');
  const data = path.join(directory, 'app');
  await mkdir(data, { recursive: true });
  await writeFile(path.join(data, 'settings.json'), JSON.stringify({ checkForUpdates: false }));
  server = await startServer(options, data, (chunk) => log.write(chunk));
  await server.on();
  await server.api('lines/add', { alias: 'TestISP' });
  const second = (await server.on()).lines.find((line) => line.alias === 'TestISP');
  assert(second);
  result.capacity = await capacity({ server, harness, directory, line: second.id });
  result.complete = true;
} catch (error) {
  result.error = error.stack;
  result.evidence = error.evidence;
  if (server) result.stats = await server.api('engine-command', { method: 'stats' }).catch(String);
  console.error(error);
  console.error(`WINDOWS CAPACITY FAILURE ${JSON.stringify(result)}`);
  process.exitCode = 1;
} finally {
  if (server) await server.quit().catch((error) => { result.quitError = error.stack; process.exitCode = 1; });
  if (harness) await targetNetwork('clean').catch((error) => { result.targetCleanupError = error.stack; process.exitCode = 1; });
  if (harness) await harness.close().catch((error) => { result.cleanupError = error.stack; process.exitCode = 1; });
  await writeFile(path.join(directory, 'report.json'), JSON.stringify(result, null, 2));
  log.end();
}
