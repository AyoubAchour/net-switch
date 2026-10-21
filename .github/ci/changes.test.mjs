import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { test } from 'node:test';
import { areaFor, changedFiles, classify, decide, groups, outputLines, run } from './changes.mjs';

// The locality rule reads the tree, so the cases run against the real file
// list plus the case's own paths.
const tracked = execFileSync('git', ['ls-files', '-z'], { cwd: new URL('../..', import.meta.url), encoding: 'utf8', maxBuffer: 256 << 20 }).split('\0').filter(Boolean);
const tree = (...paths) => new Set([...tracked, ...paths]);
const known = paths => classify(paths, tree(...paths));
const area = (path, ...more) => areaFor(path, tree(path, ...more));
const enabled = result => groups.filter(group => result.outputs[group]).sort();
const cases = {
  // Only Markdown at the repository root is documentation-only.
  docs: ['README.md', 'CHANGELOG.md', 'CONTRIBUTING.md', 'SECURITY.md'],
  frozen: ['lib/engine.mjs', 'server.mjs', 'lib/tray.cs', 'lib/tray.manifest', 'helper/main.go', 'test/engine.test.mjs', 'lib/README.md'],
  go_shared: ['internal/engine/stack/stack.go', 'cmd/netswitch/main.go', 'internal/platform/windows/meters.go', 'internal/usage/GO-LICENSE.txt'],
  go_windows: ['internal/wintun/ring_windows.go', 'internal/platform/windows/com_windows_test.go', 'cmd/netswitch/process_windows.go', 'internal/wintun/README.md'],
  go_linux: ['internal/platform/linux/socket_linux.go', 'cmd/netswitch/main_linux_arm64.go'],
  tests_linux: ['tests/linux/wire/wire.go', 'tests/linux/suite/suite.go', 'tests/linux/snap-inputs.sh', 'tests/linux/suite/snap-inputs.json', 'tests/linux/sing-box-linux.json'],
  tests_windows: ['tests/windows/client.mjs', 'tests/windows/testisp/stack_windows.go', 'tests/windows/README.md', 'tests/windows/testisp/README.md'],
  'frozen+go_shared': ['internal/apps/node-tests.json', 'internal/usage/node-zones.json', 'test/fixtures/windows-golden.json'],
};
// Expected dependencies are deliberately independent of the classifier's map.
// Changing that map must also explain why this coverage contract has changed.
const frozen = ['node', 'helper', 'installer', 'legacy_windows', 'testisp', 'go_linux', 'acceptance', 'control'];
const goShared = ['go_windows', 'go_linux', 'legacy_windows', 'testisp', 'wintun', 'acceptance', 'control'];
const expected = {
  docs: [],
  frozen,
  go_shared: goShared,
  go_windows: ['go_windows', 'legacy_windows', 'testisp', 'wintun', 'control'],
  go_linux: ['go_linux', 'acceptance'],
  tests_linux: ['go_windows', 'go_linux', 'acceptance'],
  tests_windows: ['node', 'go_windows', 'legacy_windows', 'testisp', 'control'],
  'frozen+go_shared': [...new Set([...frozen, ...goShared])],
};
for (const [name, paths] of Object.entries(cases)) {
  test(`${name}: every known path selects its complete dependency group`, () => {
    for (const path of paths) {
      assert.equal(area(path), name, path);
      assert.deepEqual(enabled(known([path])), [...expected[name]].sort(), path);
    }
  });
}

test('mixed areas take the union, never their intersection', () => {
  assert.deepEqual(enabled(known(['README.md', 'lib/tray.cs', 'internal/wintun/ring_windows.go'])), [...new Set([...expected.frozen, ...expected.go_windows])].sort());
});

test('a non-code file takes the area of the code beside it, wherever it is', () => {
  // The reviewer's case: a README beside Wintun's code is Wintun's input,
  // whether or not today's code reads it.
  assert.equal(area('internal/wintun/notes.txt'), 'go_windows');
  assert.equal(area('internal/wintun/testdata/frames.bin'), 'go_windows', 'the nearest folder with code');
  assert.equal(area('internal/engine/stack/README.md'), 'go_shared');
  assert.equal(area('tests/windows/testisp/fixture.json'), 'tests_windows');
  // Beside code of two areas: both, minus any the other already covers.
  assert.equal(area('zz/mixed/data.json', 'zz/mixed/a.mjs', 'zz/mixed/b.go'), null, 'unmapped code: everything');
  assert.equal(area('internal/zz/data.json', 'internal/zz/a.go', 'internal/zz/b_linux.go'), 'go_shared', 'go_shared selects every go_linux job');
  assert.equal(area('tests/windows/zz/data.json', 'tests/windows/zz/a.mjs', 'tests/windows/zz/b_windows.go'), 'tests_windows');
  // Beside code the map can't place, or no code at all: everything runs.
  for (const path of ['tests/oracle/README.md', 'tests/differential/README.md', 'notes/design.md', 'engine/LICENSE', 'packaging/NetSwitch.iss', 'assets/net-switch.ico']) {
    assert.equal(area(path), null, path);
    assert.equal(known([path]).full, true, path);
  }
});

test('unclassified dependencies run everything, before docs matching', () => {
  for (const path of ['.github/workflows/ci.yml', '.github/README.md', 'scripts/build-release.ps1', 'scripts/generate-gvisor.mjs', 'scripts/readme.md', 'go.mod', 'go.sum', 'helper/go.mod', 'tests/quicfixture/go.sum', 'vendor/README.md', 'third_party/gvisor/patches/fix.patch', 'package.json', 'package-lock.json', 'ui/app.js', 'packaging/versions.json', 'internal/control/http.go', 'unknown.txt', 'LICENSE', '.gitattributes', 'assets.go']) {
    assert.equal(known(['README.md', path]).full, true, path);
    assert.deepEqual(enabled(known([path])), [...groups].sort(), path);
  }
});

test('portable Go under tests/windows runs everything, because go1-linux builds ./tests/...', () => {
  for (const path of ['tests/windows/testisp/helpers.go', 'tests/windows/socket/bind.go', 'tests/windows/socket/bind_test.go', 'tests/windows/doc.go', 'tests/windows/testisp/udp_linux.go']) {
    assert.equal(area(path), null, path);
    assert.deepEqual(enabled(known([path])), [...groups].sort(), path);
  }
  for (const path of ['tests/windows/socket/bind_windows.go', 'tests/windows/testisp/udp_windows_test.go', 'tests/windows/quicprobe/main_windows_arm64.go']) assert.equal(area(path), 'tests_windows', path);
  // Data beside portable Go is the portable Go's input.
  assert.equal(area('tests/windows/socket/data.json', 'tests/windows/socket/bind.go'), null);
});

test('new files run everything, including familiar code and documentation paths', () => {
  for (const paths of Object.values(cases)) {
    for (const path of paths) assert.equal(classify([path], new Set()).full, true, path);
  }
});

test('documentation the installer ships, and Markdown below the root, is a product input', () => {
  // build-release.ps1 copies all of docs/, lib/, ui/, tools/ and licenses/,
  // and ships THIRD_PARTY_NOTICES.md and LICENSE from the root.
  for (const path of ['THIRD_PARTY_NOTICES.md', 'LICENSE', 'docs/user-guide.md', 'docs/design.md', 'docs/images/tray.png', 'ui/help.md', 'tools/help.md', 'licenses/notice.md', '.github/README.md']) {
    assert.notEqual(area(path), 'docs', path);
    assert.ok(enabled(known([path])).includes('installer'), path);
  }
});

test('deleted files use their original area and mixed deletions stay conservative', () => {
  assert.deepEqual(enabled(known(['lib/tray.cs'])), [...expected.frozen].sort());
  assert.equal(classify(['lib/tray.cs', 'old-unmapped-input'], tree('lib/tray.cs', 'old-unmapped-input')).full, true);
});

test('renames account for both source and destination and new destinations force full', () => {
  const paths = ['internal/engine/old.go', 'notes/old.md'];
  assert.equal(classify(paths, tree(paths[0])).full, true);
  assert.deepEqual(enabled(classify(['internal/engine/old.go', 'OLD.md'], tree('internal/engine/old.go', 'OLD.md'))), [...expected.go_shared].sort());
});

test('all non-PR events, tags, full label and empty diffs run everything', () => {
  for (const eventName of ['push', 'workflow_dispatch', 'release', 'merge_group']) {
    assert.equal(classify(['README.md'], new Set(['README.md']), { eventName }).full, true);
    assert.equal(decide(eventName, {}, () => { throw new Error('must not read a diff'); }).full, true);
  }
  assert.equal(classify([], new Set()).full, true);
  assert.equal(classify(['README.md'], new Set(['README.md']), { labels: ['ci:full'] }).full, true);
  assert.equal(decide('pull_request', { pull_request: { labels: [{ name: 'ci:full' }] } }).full, true);
});

test('git diff uses the merge base, no rename detection and NUL delimiters', () => {
  const base = 'a'.repeat(40), head = 'b'.repeat(40), merge = 'c'.repeat(40);
  const calls = [];
  const git = args => {
    calls.push(args);
    if (args[0] === 'merge-base') return `${merge}\n`;
    if (args[0] === 'diff') return 'lib/old.mjs\0docs/new.md\0a name\nwith a tab\t.md\0';
    return 'lib/old.mjs\0README.md\0';
  };
  const diff = changedFiles(base, head, git);
  assert.deepEqual(calls, [
    ['merge-base', base, head],
    ['diff', '--name-only', '--no-renames', '-z', merge, head, '--'],
    ['ls-tree', '-r', '--name-only', '-z', merge, '--'],
  ]);
  assert.deepEqual(diff.paths, ['lib/old.mjs', 'docs/new.md', 'a name\nwith a tab\t.md']);
  assert.deepEqual([...diff.knownPaths], ['lib/old.mjs', 'README.md']);
  assert.equal(classify(diff.paths, diff.knownPaths).full, true);
});

const prEvent = (base, defaultBranch = 'main') => ({
  pull_request: { base: { ref: base, sha: 'a'.repeat(40) }, head: { sha: 'b'.repeat(40) }, labels: [] },
  repository: { default_branch: defaultBranch },
});
const docsOnlyGit = args => args[0] === 'merge-base' ? `${'c'.repeat(40)}\n` : 'README.md\0';

test('a pull request into the default branch is classified from its diff', () => {
  const result = decide('pull_request', prEvent('main'), docsOnlyGit);
  assert.equal(result.full, false);
  assert.deepEqual(enabled(result), []);
});

test('stacked pull requests run everything, because a retarget to main starts no run', () => {
  // PR-B (feat-b -> feat-a) changes only README.md while feat-a changes lib/.
  // Skipped required checks would still count after PR-B is retargeted.
  const mustNotDiff = () => { throw new Error('must not read a diff'); };
  for (const event of [prEvent('feat-a'), prEvent('main', 'trunk'), prEvent('main', null), prEvent(null), { pull_request: { base: { ref: 'main' } } }]) {
    const result = decide('pull_request', event, mustNotDiff);
    assert.equal(result.full, true, JSON.stringify(event));
    assert.deepEqual(enabled(result), [...groups].sort());
  }
});

test('missing history and malformed event commits cannot produce a skip decision', () => {
  assert.throws(() => changedFiles('--bad', 'b'.repeat(40)), /full base and head/);
  assert.throws(() => changedFiles('a'.repeat(40), 'b'.repeat(40), () => { throw new Error('missing history'); }), /missing history/);
  assert.throws(() => decide('pull_request', { pull_request: { base: { ref: 'main', sha: 'main' } }, repository: { default_branch: 'main' } }), /full base and head/);
});

test('any classification failure runs everything and says why', () => {
  const failures = [
    ['unreadable event', () => { throw new Error('ENOENT: no event file'); }, docsOnlyGit],
    ['malformed event', () => '{not json', docsOnlyGit],
    ['missing history', () => JSON.stringify(prEvent('main')), () => { throw new Error('bad object\nmerge base'); }],
    ['malformed commits', () => JSON.stringify({ ...prEvent('main'), pull_request: { base: { ref: 'main', sha: 'HEAD~1' }, head: { sha: 'HEAD' } } }), docsOnlyGit],
  ];
  for (const [name, readEvent, git] of failures) {
    const result = run('pull_request', readEvent, git);
    assert.equal(result.full, true, name);
    assert.match(result.warning, /^Changed-file classification failed; running everything: [^\r\n]+$/, name);
    assert.equal(outputLines(result), groups.map(group => `${group}=true\n`).join(''), name);
  }
  const docs = run('pull_request', () => JSON.stringify(prEvent('main')), docsOnlyGit);
  assert.equal(docs.warning, undefined);
  assert.equal(outputLines(docs), groups.map(group => `${group}=false\n`).join(''));
});
