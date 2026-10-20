import assert from 'node:assert/strict';
import { test } from 'node:test';
import { areaFor, areas, changedFiles, classify, decide, groups } from './changes.mjs';

const known = paths => classify(paths, new Set(paths));
const enabled = result => groups.filter(group => result.outputs[group]).sort();
const cases = {
  docs: ['README.md', 'docs/design.md', 'tests/windows/README.md'],
  frozen: ['lib/engine.mjs', 'server.mjs', 'lib/tray.cs', 'helper/main.go', 'test/engine.test.mjs'],
  go_shared: ['internal/engine/stack/stack.go', 'cmd/netswitch/main.go', 'internal/platform/windows/meters.go'],
  go_windows: ['internal/wintun/ring_windows.go', 'internal/platform/windows/com_windows_test.go', 'cmd/netswitch/process_windows.go'],
  go_linux: ['internal/platform/linux/socket_linux.go', 'cmd/netswitch/main_linux_arm64.go'],
  tests_linux: ['tests/linux/wire/wire.go', 'tests/linux/suite/suite.go', 'tests/linux/snap-inputs.sh'],
  tests_windows: ['tests/windows/client.mjs', 'tests/windows/testisp/stack_windows.go'],
};
for (const [area, paths] of Object.entries(cases)) {
  test(`${area}: every known path selects its complete dependency group`, () => {
    for (const path of paths) {
      assert.equal(areaFor(path), area);
      assert.deepEqual(enabled(known([path])), [...areas[area]].sort());
    }
  });
}

test('mixed areas take the union, never their intersection', () => {
  assert.deepEqual(enabled(known(['README.md', 'lib/tray.cs', 'internal/wintun/ring_windows.go'])), [...new Set([...areas.frozen, ...areas.go_windows])].sort());
});

test('unclassified dependencies and fixtures run everything, before docs matching', () => {
  for (const path of ['.github/workflows/ci.yml', '.github/README.md', 'scripts/build-release.ps1', 'scripts/generate-gvisor.mjs', 'scripts/readme.md', 'go.mod', 'go.sum', 'helper/go.mod', 'tests/quicfixture/go.sum', 'vendor/README.md', 'third_party/gvisor/patches/fix.patch', 'package.json', 'package-lock.json', 'ui/app.js', 'packaging/versions.json', 'internal/control/http.go', 'internal/apps/node-tests.json', 'test/fixtures/README.md', 'tests/linux/testdata/input.md', 'unknown.txt', 'internal/new.data', 'assets.go']) {
    assert.equal(known(['README.md', path]).full, true, path);
    assert.deepEqual(enabled(known([path])), [...groups].sort(), path);
  }
});

test('new files run everything, including familiar code and documentation paths', () => {
  for (const paths of Object.values(cases)) {
    for (const path of paths) assert.equal(classify([path], new Set()).full, true, path);
  }
});

test('deleted files use their original area and mixed deletions stay conservative', () => {
  assert.deepEqual(enabled(known(['lib/tray.cs'])), [...areas.frozen].sort());
  assert.equal(known(['lib/tray.cs', 'old-unmapped-input']).full, true);
});

test('renames account for both source and destination and new destinations force full', () => {
  const paths = ['internal/engine/old.go', 'docs/old.md'];
  assert.equal(classify(paths, new Set([paths[0]])).full, true);
  assert.deepEqual(enabled(known(paths)), [...areas.go_shared].sort());
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

test('missing history and malformed event commits cannot produce a skip decision', () => {
  assert.throws(() => changedFiles('--bad', 'b'.repeat(40)), /full base and head/);
  assert.throws(() => changedFiles('a'.repeat(40), 'b'.repeat(40), () => { throw new Error('missing history'); }), /missing history/);
  assert.throws(() => decide('pull_request', {}), /full base and head/);
});
