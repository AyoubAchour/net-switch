// Shared launch/identity boundary for Node and the milestone-one Go service.
// Callers retain their routing assertions and cleanup ownership.
import { spawn, execFile } from 'node:child_process';
import { createHash } from 'node:crypto';
import { readFile, realpath } from 'node:fs/promises';
import path from 'node:path';
import { promisify } from 'node:util';
import { fileURLToPath } from 'node:url';
import { launchOptions, serverCommand } from '../tests/windows/launch.mjs';

const run = promisify(execFile);
export const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
export const nodeEntry = path.join(root, 'scripts', 'server-under-test-node.mjs');
export const launchSpec = launchOptions();
if (launchSpec.entry && !process.argv.includes('--server-entry')) launchSpec.entry = nodeEntry;
export const serverExecutable = launchSpec.server;
export const engineExecutable = launchSpec.engine;
export const isNodeServer = launchSpec.entry !== null;

export async function recordExecutable(label, executable, args = ['--version']) {
  const resolved = await realpath(executable);
  const sha256 = createHash('sha256').update(await readFile(resolved)).digest('hex');
  const { stdout, stderr } = await run(resolved, args, { windowsHide: true, timeout: 15_000 });
  const version = `${stdout}${stderr}`.trim();
  console.log(`${label}: ${JSON.stringify({ path: resolved, version, sha256 })}`);
  return { path: resolved, version, sha256 };
}
export async function recordServerAndEngine() {
  await recordExecutable('SERVER UNDER TEST', serverExecutable, launchSpec.serverVersionArgs);
  if (isNodeServer) {
    for (const entry of [launchSpec.entry, path.join(root, 'lib', 'server-factory.mjs')]) {
      console.log(`NODE ENTRY: ${JSON.stringify({ path: entry, sha256: createHash('sha256').update(await readFile(entry)).digest('hex') })}`);
    }
  }
  await recordExecutable('ENGINE UNDER TEST', engineExecutable, launchSpec.engineVersionArgs);
}
export function launchServer(dataDir, mode = 'proxy') {
  const [executable, args] = serverCommand(launchSpec, dataDir, { proxy: mode === 'proxy' });
  return spawn(executable, args, { cwd: root, windowsHide: true, stdio: ['ignore', 'pipe', 'pipe'] });
}
