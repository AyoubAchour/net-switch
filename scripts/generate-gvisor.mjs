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
  // Temporary round-2 mutation proof; removed after the hosted evidence is saved.
  const mutation = process.env.NETSWITCH_RTO_MUTATION;
  if (mutation) {
    if (diffOnly) throw new Error('Mutation is not allowed in patch diff mode');
    const mutations = {
      ack: ['snd.go', 'numLost > 0 && !s.FastRecovery.Active && s.state != tcpip.RTORecovery', 'numLost > 0 && !s.FastRecovery.Active'],
      timer: ['rack.go', 'numLost == 0 || rc.snd.state == tcpip.RTORecovery', 'numLost == 0'],
      duplicate: ['snd.go', '\tif s.state == tcpip.RTORecovery {\n\t\treturn false\n\t}\n', ''],
    };
    if (!Object.hasOwn(mutations, mutation)) throw new Error(`Unknown mutation: ${mutation}`);
    const [name, before, after] = mutations[mutation];
    const file = path.join(staging, 'pkg/tcpip/transport/tcp', name);
    const content = fs.readFileSync(file, 'utf8');
    if (content.split(before).length !== 2) throw new Error(`Mutation ${mutation} must match exactly once`);
    fs.writeFileSync(file, content.replace(before, after));
    console.log(`MUTATION: removed only the ${mutation} timeout-recovery guard`);
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
