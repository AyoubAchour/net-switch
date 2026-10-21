// Reproducible dependency output. Edit the manifest and patch, never the tree.
import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const patches = fs.readdirSync(path.join(root, 'third_party'))
  .filter(name => /^gvisor-.*\.patch$/.test(name)).sort();
const args = process.argv.slice(2);
const diffOnly = args[0] === '--diff';
const selected = args[1];
if (!patches.length || (args.length && (!diffOnly || args.length !== 2 || !patches.includes(selected)))) {
  throw new Error(`Usage: generate-gvisor.mjs [--diff <patch>]; patches in order: ${patches.join(', ')}`);
}
const go = process.env.GO_BINARY || 'go';
function run(exe, args, cwd = root) {
  const result = spawnSync(exe, args, { cwd, encoding: 'utf8', windowsHide: true, maxBuffer: 8 << 20 });
  if (result.error || result.status !== 0) throw new Error(`${exe} ${args.join(' ')}: ${result.error || result.stderr || result.stdout}`);
  return result.stdout;
}
const mod = fs.readFileSync(path.join(root, 'go.mod'), 'utf8');
const goVersion = mod.match(/^go (\d+\.\d+\.\d+)$/m)?.[1];
if (!goVersion) throw new Error('Missing exact Go toolchain pin in go.mod');
if (process.env.GOTOOLCHAIN !== 'local' || run(go, ['env', 'GOVERSION']).trim() !== `go${goVersion}`) {
  throw new Error(`Use pinned Go ${goVersion} with GOTOOLCHAIN=local`);
}
const moduleName = 'gvisor.dev/gvisor';
const version = mod.match(/^\s*(?:require\s+)?gvisor\.dev\/gvisor\s+(v\S+)\s*$/m)?.[1];
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
// Regenerate one patch against upstream plus all its predecessors. The caller
// saves stdout with their file-editing tool; this never rewrites a patch.
try {
  for (const name of files) {
    if (!name || path.isAbsolute(name) || name.split('/').includes('..') || name.includes('\\')) throw new Error(`Invalid manifest path: ${name}`);
    const destination = path.join(staging, name);
    fs.mkdirSync(path.dirname(destination), { recursive: true });
    fs.copyFileSync(path.join(upstream.Dir, name), destination);
  }
  for (const patch of patches) {
    if (diffOnly && patch === selected) {
      run('git', ['init', '--quiet'], staging);
      run('git', ['-c', 'core.autocrlf=false', 'add', '.'], staging);
    }
    run('git', ['-c', 'core.autocrlf=false', '-c', 'core.eol=lf', 'apply',
      ...(diffOnly && patch === selected ? ['--recount'] : []),
      '--unsafe-paths', '--whitespace=nowarn', path.join(root, 'third_party', patch)], staging);
    if (diffOnly && patch === selected) break;
  }
  if (diffOnly) {
    // Include regression tests introduced by the patch, not just upstream files.
    run('git', ['-c', 'core.autocrlf=false', 'add', '--intent-to-add', '.'], staging);
    process.stdout.write(run('git', [
      '-c', 'core.autocrlf=false', '-c', 'core.eol=lf',
      '-c', 'diff.noprefix=false', '-c', 'diff.mnemonicPrefix=false',
      '-c', 'diff.suppressBlankEmpty=false',
      'diff', '--no-ext-diff', '--no-textconv', '--no-color',
      '--src-prefix=a/', '--dst-prefix=b/', '--line-prefix=',
      '--output-indicator-new=+', '--output-indicator-old=-', '--output-indicator-context= ',
      '--no-renames', '--text', '--unified=3', '--inter-hunk-context=0',
      '--diff-algorithm=myers', '--indent-heuristic', '--abbrev=7',
    ], staging));
  } else {
    const target = path.resolve(root, 'third_party', 'gvisor');
    if (path.relative(root, target) !== path.join('third_party', 'gvisor')) throw new Error('Generated target escapes repository');
    if (fs.existsSync(target) && fs.lstatSync(target).isSymbolicLink()) throw new Error('Generated target is a symlink');
    fs.rmSync(target, { recursive: true, force: true });
    fs.mkdirSync(target, { recursive: true });
    fs.cpSync(staging, target, { recursive: true });
    console.log(`Generated ${filesIn(staging).length} gVisor files from verified ${version} plus ${patches.join(', ')}`);
  }
} finally {
  if (path.dirname(staging) !== tmpdir() || !path.basename(staging).startsWith('netswitch-gvisor-')) throw new Error('Unexpected temporary directory');
  fs.rmSync(staging, { recursive: true, force: true });
}
