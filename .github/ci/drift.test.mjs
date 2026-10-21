import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { posix } from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { areaFor, areas, groups } from './changes.mjs';
import { evaluate, readWorkflow, runnerOS, truthy } from './workflows.mjs';

// The classifier maps files to job groups by where they live. A test, script
// or Go file that reads a file from another area breaks that map silently:
// changing the file would skip the job that reads it. This test follows what
// each gated job runs, and what those files import, read, spawn or embed, and
// fails if a reached file's area wouldn't select a job that reaches it.

const root = fileURLToPath(new URL('../../', import.meta.url));
const tracked = execFileSync('git', ['ls-files', '-z'], { cwd: root, encoding: 'utf8', maxBuffer: 256 * 1024 * 1024 }).split('\0').filter(Boolean);
const trackedSet = new Set(tracked);
const directories = new Set(tracked.flatMap(file => file.split('/').slice(0, -1).map((_, index, parts) => parts.slice(0, index + 1).join('/'))));
const read = path => readFileSync(posix.join(root, path), 'utf8').replace(/\r\n/g, '\n');
const generated = /^(?:vendor|third_party|dist)\//;
const scannable = path => /\.(?:mjs|js|go|ps1|sh)$/.test(path) && !generated.test(path);
const glob = pattern => new RegExp(`^${pattern.split('\0').map(part => part.replace(/[.*+?^${}()|[\]\\]/g, '\\$&').replace(/\\\*/g, '[^/]*')).join('[^/]*')}$`);

// References these readers make that only some of their jobs exercise.
// Each one narrows the jobs carried along that reference; each must still be
// in use, so a stale entry fails too.
export const narrowed = [{
  from: 'scripts/e2e-routing.mjs', to: /^internal\/platform\/worker\//, groups: ['control'],
  why: 'it runs go test ./internal/platform/worker only against the Go control server (!isNodeServer), which only the Control jobs start',
}];

function resolve(candidate, directory) {
  let path = candidate.replace(/^\$PSScriptRoot[\\/]/, './').replace(/\\/g, '/')
    // Interpolations (${x}, $(x), $x) match one path segment's worth of text.
    .replace(/\$\{[^}]*\}|\$\([^)]*\)|\$\w+/g, '\0');
  // Paths only: not words, URLs, '/' separators or '..' on their own.
  if (!/[/.]/.test(path) || !/[a-z0-9]/i.test(path) || /[\s:]/.test(path)) return [];
  // "$dir/$name" says nothing about which file it is.
  if (path.includes('\0') && !path.split('/').some(segment => !segment.includes('\0') && /[a-z]/i.test(segment))) return [];
  // Imports resolve from the file; spawned commands from the repository root.
  const bases = path.startsWith('../') ? [posix.join(directory, path)] : [posix.join(directory, path), posix.normalize(path)];
  const found = new Set();
  for (let base of bases) {
    base = base.replace(/\/+$/, '');
    if (!base || base === '.' || base.startsWith('../')) continue;
    if (base.includes('\0')) {
      const pattern = glob(base);
      for (const file of tracked) if (pattern.test(file)) found.add(file);
    } else if (trackedSet.has(base)) found.add(base);
    else if (directories.has(base)) for (const file of tracked) if (file.startsWith(`${base}/`)) found.add(file);
  }
  return [...found];
}

export function references(file) {
  const directory = posix.dirname(file);
  const comment = /\.(?:ps1|sh)$/.test(file) ? /^\s*#/ : /^\s*\/\/(?!go:embed)/;
  const text = read(file).split('\n').filter(line => !comment.test(line)).join('\n');
  const candidates = [];
  const literal = /'([^'\n]*)'|"([^"\n]*)"|`([^`\n]*)`/g;
  // Scripts name files in plain strings. Go strings are mostly data, so for Go
  // only literals passed straight to a file call count, plus joins and embeds.
  const direct = file.endsWith('.go') ? /\b(?:ReadFile|ReadDir|Open|OpenFile|Stat|Lstat)\(\s*("[^"\n]*")/g : literal;
  for (const match of text.matchAll(direct)) {
    if (file.endsWith('.go')) candidates.push(match[1].slice(1, -1));
    else candidates.push(match[1] ?? match[2] ?? match[3]);
  }
  // path.join(root, 'lib', 'tray.cs'), filepath.Join(repo, "tests", "x.json")
  for (const match of text.matchAll(/\b(?:join|Join|resolve)\s*\(((?:[^()\n]|\([^()\n]*\))*)\)/g)) {
    const parts = [...match[1].matchAll(literal)].map(part => part[1] ?? part[2] ?? part[3]);
    if (parts.length > 1) candidates.push(parts.join('/'));
  }
  for (const match of text.matchAll(/^\/\/go:embed\s+(.+)$/gm)) candidates.push(...match[1].trim().split(/\s+/));
  return [...new Set(candidates.flatMap(candidate => resolve(candidate, directory)))].filter(path => path !== file);
}

// Files a job's steps start: named scripts, test files, "npm test".
function jobRoots(job) {
  const npmTest = JSON.parse(read('package.json')).scripts.test;
  const roots = new Set();
  for (const step of job.steps) {
    if (step.if && /runner\.os|matrix\./.test(step.if)) {
      const runs = job.matrix.some(entry => truthy(evaluate(step.if, {
        runner: { os: runnerOS(entry.runner) }, matrix: entry, inputs: {}, steps: {},
        functions: { always: () => true, success: () => true, failure: () => false, cancelled: () => false },
      })));
      if (!runs) continue;
    }
    for (const token of step.text.replace(/\bnpm test\b/g, npmTest).split(/[\s'"`(),;=|&>]+/)) {
      const path = token.replace(/^\.\//, '');
      if (path.includes('*')) { const pattern = glob(path.replace(/\*/g, '\0')); for (const file of tracked) if (pattern.test(file)) roots.add(file); }
      else if (trackedSet.has(path)) roots.add(path);
    }
  }
  return roots;
}

export function driftProblems(areaOf = areaFor, groupsOf = areas) {
  const reach = new Map(); // file -> Map(group -> file that carried it there)
  const queue = [];
  const used = new Set();
  const systems = new Map(groups.map(group => [group, new Set()]));
  const add = (file, carried, from) => {
    // A job never compiles Go files for the other OS.
    const os = /_windows(?:_\w+)?(?:_test)?\.go$/.test(file) ? 'Windows' : /_linux(?:_\w+)?(?:_test)?\.go$/.test(file) ? 'Linux' : null;
    if (os) carried = carried.filter(group => systems.get(group).has(os));
    let groupsHere = reach.get(file);
    if (!groupsHere) reach.set(file, groupsHere = new Map());
    let grew = false;
    for (const group of carried) if (!groupsHere.has(group)) { groupsHere.set(group, from); grew = true; }
    if (grew && scannable(file)) queue.push(file);
  };
  const jobs = ['ci', 'control', 'linux-acceptance'].flatMap(name => [...readWorkflow(read(`.github/workflows/${name}.yml`)).jobs.values()].map(job => ({
    job, label: `${name}.yml ${job.id}`,
    group: [...(job.if ?? '').matchAll(/needs\.changes\.outputs\.(\w+)/g)].map(match => match[1]),
  }))).filter(({ group }) => group.length === 1); // not the classifier or manual investigations
  for (const { job, group } of jobs) for (const entry of job.matrix) systems.get(group[0]).add(runnerOS(entry.runner));
  for (const { job, group, label } of jobs) for (const file of jobRoots(job)) add(file, group, label);
  // Go code is built by package patterns, not by name: its own area says which
  // jobs build it. An unmapped Go file is assumed built wherever shared Go is.
  for (const file of tracked) {
    if (file.endsWith('.go') && !generated.test(file)) add(file, groupsOf[areaOf(file) ?? 'go_shared'], 'its own area');
  }
  const readersOf = new Map();
  while (queue.length) {
    const file = queue.shift();
    if (!readersOf.has(file)) readersOf.set(file, references(file));
    for (const target of readersOf.get(file)) {
      let carried = [...reach.get(file).keys()];
      const narrow = narrowed.find(entry => entry.from === file && entry.to.test(target));
      if (narrow) { used.add(narrow); carried = carried.filter(group => narrow.groups.includes(group)); }
      add(target, carried, file);
    }
  }
  const problems = [];
  for (const [file, groupsHere] of reach) {
    const area = areaOf(file);
    if (area === null) continue;
    for (const [group, from] of groupsHere) {
      if (!groupsOf[area].includes(group)) problems.push(`${file} (area ${area}) is read by ${from}, which a ${group} job runs, but its area doesn't select ${group}`);
    }
  }
  for (const entry of narrowed) if (!used.has(entry)) problems.push(`stale narrowed reference from ${entry.from}`);
  return { problems, reach };
}

const current = driftProblems();

test('every file a gated job reads selects that job when it changes', () => {
  assert.deepEqual(current.problems, []);
});

test('the reader graph reaches the known cross-area reads', () => {
  // Guards against a parsing change that silently finds nothing.
  const groupsAt = file => [...(current.reach.get(file)?.keys() ?? [])].sort();
  assert.ok(current.reach.size > 300, `only ${current.reach.size} files reached`);
  assert.ok(groupsAt('test/traces.test.mjs').includes('node'));
  assert.ok(groupsAt('test/traces.test.mjs').includes('legacy_windows'), 'engine job runs npm test');
  assert.ok(groupsAt('internal/control/http.go').includes('node'), 'test/traces.test.mjs reads http.go');
  assert.ok(groupsAt('tests/windows/launch.mjs').includes('node'));
  assert.ok(groupsAt('tests/windows/launch.mjs').includes('control'));
  assert.ok(groupsAt('tests/windows/testisp/harness.mjs').includes('testisp'));
  assert.deepEqual(groupsAt('tests/linux/engine/singbox/config.mjs').filter(group => group === 'acceptance'), ['acceptance'], 'driver_linux.go runs config.mjs');
  assert.ok(groupsAt('lib/engine.mjs').includes('acceptance'), 'config.mjs imports lib/engine.mjs');
  assert.ok(groupsAt('tests/linux/suite/snap-inputs.json').includes('acceptance'), 'go:embed and the workflow');
  assert.ok(groupsAt('lib/lines.mjs').includes('go_linux'), 'the differential oracle runs on Linux');
  assert.ok(!groupsAt('lib/lines.mjs').includes('go_windows'), 'its step is Linux-only');
  assert.ok(groupsAt('internal/platform/worker/supervisor.go').includes('control'));
  assert.ok(!groupsAt('internal/platform/worker/supervisor.go').includes('node'), 'narrowed to Control');
});

test('a map that misses a reader fails the drift check', () => {
  const mapped = (path, area) => file => file === path ? area : areaFor(file);
  const fails = (areaOf, groupsOf, pattern) => assert.ok(driftProblems(areaOf, groupsOf).problems.some(problem => pattern.test(problem)), String(pattern));
  // The exception this test replaced: Node reads this Go source.
  fails(mapped('internal/control/http.go', 'go_shared'), areas, /^internal\/control\/http\.go .* node job/);
  fails(mapped('tests/windows/launch.mjs', 'tests_linux'), areas, /^tests\/windows\/launch\.mjs .* (node|control) job/);
  fails(mapped('tests/linux/engine/singbox/config.mjs', 'go_windows'), areas, /config\.mjs .* acceptance job/);
  fails(areaFor, { ...areas, frozen: areas.frozen.filter(group => group !== 'acceptance') }, /^lib\/engine\.mjs .* acceptance job/);
  fails(areaFor, { ...areas, tests_linux: areas.tests_linux.filter(group => group !== 'acceptance') }, /^tests\/linux\/suite\/snap-inputs\.json .* acceptance job/);
});
