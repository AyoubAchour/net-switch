// Shared launch/identity boundary for Node and the milestone-one Go service.
// Callers retain their routing assertions and cleanup ownership.
import { spawn, execFile } from 'node:child_process';
import { createHash } from 'node:crypto';
import { readFile, realpath } from 'node:fs/promises';
import path from 'node:path';
import { promisify } from 'node:util';
import { fileURLToPath } from 'node:url';

const run = promisify(execFile);
export const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const flag = (name) => {
  const index = process.argv.indexOf(name);
  if (index < 0) return null;
  if (!process.argv[index + 1]) throw new Error(`${name} requires a path`);
  return path.resolve(process.argv[index + 1]);
};
export const serverExecutable = flag('--server-executable') ?? process.execPath;
export const engineExecutable = flag('--engine-executable') ?? path.join(flag('--engine-dir') ?? path.join(root, 'engine'), 'sing-box.exe');
export const isNodeServer = /^(?:node|nodejs)(?:\.exe)?$/i.test(path.basename(serverExecutable));
export const nodeEntry = path.join(root, 'scripts', 'server-under-test-node.mjs');

export async function recordExecutable(label, executable, args = ['--version']) {
  const resolved = await realpath(executable);
  const sha256 = createHash('sha256').update(await readFile(resolved)).digest('hex');
  const { stdout, stderr } = await run(resolved, args, { windowsHide: true, timeout: 15_000 });
  const version = `${stdout}${stderr}`.trim();
  console.log(`${label}: ${JSON.stringify({ path: resolved, version, sha256 })}`);
  return { path: resolved, version, sha256 };
}
export async function recordServerAndEngine() {
  await recordExecutable('SERVER UNDER TEST', serverExecutable);
  if (isNodeServer) {
    for (const entry of [nodeEntry, path.join(root, 'lib', 'server-factory.mjs')]) {
      console.log(`NODE ENTRY: ${JSON.stringify({ path: entry, sha256: createHash('sha256').update(await readFile(entry)).digest('hex') })}`);
    }
  }
  await recordExecutable('ENGINE UNDER TEST', engineExecutable, ['version']);
}
export function launchServer(dataDir, mode = 'proxy') {
  const args = [
    ...(isNodeServer ? [nodeEntry] : ['--root', root]),
    ...(mode === 'proxy' ? ['--dev-proxy'] : []),
    '--user-data', dataDir, '--machine-data', dataDir,
    '--engine-executable', engineExecutable,
  ];
  return spawn(serverExecutable, args, { cwd: root, windowsHide: true, stdio: ['ignore', 'pipe', 'pipe'] });
}
