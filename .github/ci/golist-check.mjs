// Checks golist.mjs against the go command itself. It needs Go, so the
// golist-oracle job in ci.yml runs it; that job has no gate, so it runs
// whatever the classifier decides.
//
// 1. Every go command a gated job runs, as drift.mjs parses it from the
//    workflows, with that job's GOOS, GOARCH, -tags (and -race) and GOFLAGS:
//    go list and golist.mjs must select exactly the same files.
// 2. golist.mjs leaves architecture and custom tags open where drift.mjs
//    uses it, which must cover every setting: for the root module, the union
//    over amd64 and arm64 with every custom tag off and on (scripts start go
//    test with close_*_disabled tags) must equal the open selection.
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { isAbsolute, posix, relative } from 'node:path';
import { driftProblems } from './drift.mjs';
import { GoTree, buildLine } from './golist.mjs';
import { generated, repoView } from './repo.mjs';

const root = execFileSync('git', ['rev-parse', '--show-toplevel'], { encoding: 'utf8' }).trim();
const repo = repoView();
const tree = new GoTree(repo, { skip: path => generated.test(path) });
const goFiles = repo.tracked.filter(file => file.endsWith('.go') && !generated.test(file));
const custom = [...new Set(goFiles.flatMap(file => (buildLine(repo.read(file)) ?? '').match(/[\w.]+/g) ?? []))]
  .filter(tag => !['linux', 'windows', 'unix', 'amd64', 'arm64'].includes(tag)).sort();
console.log(`custom tags: ${custom.join(' ') || '(none)'}`);
// CGO_ENABLED only changes which files compile through cgo files and the cgo
// tag. There are none, so every listing below runs without cgo.
assert.deepEqual(goFiles.filter(file => /^import\s+"C"|^\s+"C"$/m.test(repo.read(file)) || /\bcgo\b/.test(buildLine(repo.read(file)) ?? '')), [], 'cgo files would make CGO_ENABLED matter');

// go list -json writes one object after another.
const objects = text => text.trim() ? text.trim().split(/\n(?=\{)/).map(part => JSON.parse(part)) : [];
const fields = 'ImportPath,Dir,Module,Error,Standard,GoFiles,TestGoFiles,XTestGoFiles,EmbedFiles,TestEmbedFiles,XTestEmbedFiles';

function listed({ dir, goos, goarch, tags, tests, goflags, patterns }) {
  const started = Date.now();
  const output = execFileSync('go', ['list', '-e', '-deps', ...(tests ? ['-test'] : []), `-tags=${tags.join(',')}`, `-json=${fields}`, ...patterns], {
    cwd: posix.join(root, dir), encoding: 'utf8', maxBuffer: 256 << 20,
    env: { ...process.env, GOOS: goos, GOARCH: goarch, CGO_ENABLED: '0', GOFLAGS: goflags ?? '' },
  });
  const files = new Set();
  for (const pkg of objects(output)) {
    if (pkg.Standard) continue;
    const at = relative(root, pkg.Dir).replace(/\\/g, '/');
    // Outside the repository (the module cache, the generated test main)
    // or a generated tree golist.mjs doesn't follow.
    if (at.startsWith('..') || isAbsolute(at) || generated.test(`${at}/`)) continue;
    assert.equal(pkg.Error, undefined, `${goos}/${goarch} ${pkg.ImportPath}: ${pkg.Error?.Err}`);
    for (const name of [pkg.GoFiles, pkg.TestGoFiles, pkg.XTestGoFiles, pkg.EmbedFiles, pkg.TestEmbedFiles, pkg.XTestEmbedFiles].flat().filter(Boolean)) {
      if (isAbsolute(name)) continue;
      files.add(at ? posix.join(at, name) : name);
    }
  }
  return { files, seconds: (Date.now() - started) / 1000 };
}

function selected(dirs, goos, tests, exact) {
  const files = new Set();
  for (const file of tree.load(dirs, goos, tests, exact).keys()) {
    files.add(file);
    const { files: embedded, errors } = tree.embeds(file);
    assert.deepEqual(errors, [], file);
    for (const path of embedded) files.add(path);
  }
  return files;
}

const compare = (label, go, ours) => {
  const missing = [...go].filter(file => !ours.has(file)).sort();
  const extra = [...ours].filter(file => !go.has(file)).sort();
  assert.deepEqual(missing, [], `${label}: go list compiles or embeds these, golist.mjs doesn't`);
  assert.deepEqual(extra, [], `${label}: golist.mjs selects these, go list doesn't`);
};

// 1. The workflows' own settings.
const unquote = value => value?.replace(/^'(.*)'$/, '$1');
const groups = new Map();
for (const command of driftProblems().go) {
  const goos = { Windows: 'windows', Linux: 'linux' }[command.os];
  const goarch = /-arm$/.test(command.runner) || /^windows-11-arm/.test(command.runner) ? 'arm64' : 'amd64';
  const tags = [...new Set([...command.tags, ...(command.race ? ['race'] : [])])].sort();
  const goflags = unquote(command.env.GOFLAGS);
  const key = JSON.stringify([command.dir, goos, goarch, tags, command.tests, goflags]);
  if (!groups.has(key)) groups.set(key, { dir: command.dir, goos, goarch, tags, tests: command.tests, goflags, patterns: new Set(), jobs: new Set() });
  const group = groups.get(key);
  for (const pattern of command.patterns) group.patterns.add(pattern);
  group.jobs.add(command.label);
}
assert.ok(groups.size >= 20, `only ${groups.size} go settings parsed from the workflows`);
assert.ok([...groups.values()].some(group => group.tags.includes('control_test_https') && group.goos === 'windows'), "Control's control_test_https build");
let total = 0;
for (const group of groups.values()) {
  const patterns = [...group.patterns].sort();
  const dirs = [...new Set(patterns.flatMap(pattern => tree.expand(pattern, group.dir)))];
  const exact = { goarch: group.goarch, tags: new Set(group.tags) };
  // As go would evaluate the constraints, -tags x selects //go:build x and
  // rules out //go:build !x; close_fence_disabled stays off unless named.
  const constraint = [group.goos, group.goarch, ...group.tags, ...custom.filter(tag => !group.tags.includes(tag)).map(tag => `!${tag}`)].join(' && ');
  const { files, seconds } = listed({ ...group, patterns });
  total += seconds;
  const label = `${group.dir || '.'} ${constraint}${group.tests ? ' with tests' : ''} [${group.goflags ?? 'no GOFLAGS'}]`;
  compare(label, files, selected(dirs, group.goos, group.tests, exact));
  // The open selection drift.mjs uses covers this exact one.
  const open = selected(dirs, group.goos, group.tests);
  assert.deepEqual([...files].filter(file => !open.has(file)), [], `${label}: missing from the open selection`);
  console.log(`agree: ${label}: ${files.size} files, ${patterns.join(' ')} (${[...group.jobs].sort().join(', ')}; go list ${seconds.toFixed(1)} s)`);
}

// 2. The open selection over every setting, for the root module's trees.
const patterns = ['./internal/...', './cmd/...', './tests/...'];
for (const goos of ['windows', 'linux']) {
  const union = new Set();
  for (const goarch of ['amd64', 'arm64']) {
    for (const tags of [[], custom]) {
      const { files, seconds } = listed({ dir: '', goos, goarch, tags, tests: true, goflags: '-mod=vendor', patterns });
      total += seconds;
      for (const file of files) union.add(file);
    }
  }
  compare(`GOOS=${goos}, every architecture and tag setting`, union, selected(patterns.flatMap(pattern => tree.expand(pattern, '')), goos, true));
  assert.ok(union.size > 100, `GOOS=${goos}: only ${union.size} files listed`);
  console.log(`agree: GOOS=${goos} open selection over amd64/arm64 and tags off/on: ${union.size} files`);
}
console.log(`${groups.size} workflow settings and 8 open listings agree; go list took ${total.toFixed(1)} s in all`);
