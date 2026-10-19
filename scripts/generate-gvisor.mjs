// Reproducible dependency output. Edit the manifest and patch, never the tree.
import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const go = process.env.GO_BINARY || 'go';
function run(exe, args, cwd = root) {
  const result = spawnSync(exe, args, { cwd, encoding: 'utf8', windowsHide: true, maxBuffer: 8 << 20 });
  if (result.error || result.status !== 0) throw new Error(`${exe} ${args.join(' ')}: ${result.error || result.stderr || result.stdout}`);
  return result.stdout;
}
const pins = JSON.parse(fs.readFileSync(path.join(root, 'packaging/versions.json'), 'utf8'));
if (process.env.GOTOOLCHAIN !== 'local' || run(go, ['env', 'GOVERSION']).trim() !== `go${pins.go.version}`) {
  throw new Error(`Use pinned Go ${pins.go.version} with GOTOOLCHAIN=local`);
}
const moduleName = 'gvisor.dev/gvisor';
const mod = fs.readFileSync(path.join(root, 'go.mod'), 'utf8');
const version = mod.match(/^require gvisor\.dev\/gvisor (v\S+)$/m)?.[1];
if (!version) throw new Error('Missing exact gVisor module pin');
const upstream = JSON.parse(run(go, ['mod', 'download', '-json', `${moduleName}@${version}`]));
const sums = fs.readFileSync(path.join(root, 'go.sum'), 'utf8').split(/\r?\n/);
const expected = sums.find(line => line.startsWith(`${moduleName} ${version} `))?.split(' ')[2];
if (!expected || upstream.Sum !== expected || !upstream.Dir) throw new Error('Upstream module checksum does not match go.sum');

function filesIn(dir, prefix = '') {
  return fs.readdirSync(dir, { withFileTypes: true }).flatMap(entry => {
    const name = prefix + entry.name;
    if (entry.isSymbolicLink()) throw new Error(`Unexpected symlink: ${name}`);
    return entry.isDirectory() ? filesIn(path.join(dir, entry.name), `${name}/`) : [name];
  });
}
// Verify the extracted module as well as the downloaded zip. This is Go's h1
// format: SHA-256 of sorted "file SHA-256, two spaces, module path, newline".
// go mod verify alone does not check a module hidden by a local replacement.
const summary = createHash('sha256');
for (const name of filesIn(upstream.Dir).sort()) {
  if (name.includes('\n')) throw new Error('Invalid module filename');
  const digest = createHash('sha256').update(fs.readFileSync(path.join(upstream.Dir, name))).digest('hex');
  summary.update(`${digest}  ${moduleName}@${version}/${name}\n`);
}
if (`h1:${summary.digest('base64')}` !== expected) throw new Error('Extracted upstream module was modified');

const files = fs.readFileSync(path.join(root, 'third_party/gvisor.files'), 'utf8').trim().split(/\r?\n/);
const staging = fs.mkdtempSync(path.join(tmpdir(), 'netswitch-gvisor-'));
try {
  for (const name of files) {
    if (!name || path.isAbsolute(name) || name.split('/').includes('..') || name.includes('\\')) throw new Error(`Invalid manifest path: ${name}`);
    const destination = path.join(staging, name);
    fs.mkdirSync(path.dirname(destination), { recursive: true });
    fs.copyFileSync(path.join(upstream.Dir, name), destination);
  }
  run('git', ['-c', 'core.autocrlf=false', '-c', 'core.eol=lf', 'apply', '--unsafe-paths', '--whitespace=nowarn', path.join(root, 'third_party/gvisor-timewait.patch')], staging);
  const target = path.resolve(root, 'third_party', 'gvisor');
  if (path.relative(root, target) !== path.join('third_party', 'gvisor')) throw new Error('Generated target escapes repository');
  if (fs.existsSync(target) && fs.lstatSync(target).isSymbolicLink()) throw new Error('Generated target is a symlink');
  fs.rmSync(target, { recursive: true, force: true });
  fs.mkdirSync(target, { recursive: true });
  fs.cpSync(staging, target, { recursive: true });
  console.log(`Generated ${files.length} gVisor files from verified ${version} plus gvisor-timewait.patch`);
} finally {
  if (path.dirname(staging) !== tmpdir() || !path.basename(staging).startsWith('netswitch-gvisor-')) throw new Error('Unexpected temporary directory');
  fs.rmSync(staging, { recursive: true, force: true });
}
