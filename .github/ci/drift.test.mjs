import assert from 'node:assert/strict';
import { test } from 'node:test';
import { areaFor, areas } from './changes.mjs';
import { driftProblems } from './drift.mjs';
import { buildLine, constraintHolds, nameHolds } from './golist.mjs';
import { repoView } from './repo.mjs';

// See drift.mjs. These tests run the guard on the real tree, then on in-memory
// mutations of the map, the workflows and the source, each of which must fail.

const current = driftProblems();

test('every file a gated job reads selects that job when it changes', () => {
  assert.deepEqual(current.problems, []);
});

test('the reader graph reaches the known cross-area reads', () => {
  // Guards against a parsing change that silently finds nothing.
  const { groupsAt } = current;
  assert.ok(current.reach.size > 300, `only ${current.reach.size} files reached`);
  assert.ok(groupsAt('test/traces.test.mjs').includes('node'));
  assert.ok(groupsAt('test/traces.test.mjs').includes('legacy_windows'), 'engine job runs npm test');
  assert.ok(groupsAt('internal/control/http.go').includes('node'), 'test/traces.test.mjs reads http.go');
  assert.ok(groupsAt('tests/windows/launch.mjs').includes('node'));
  assert.ok(groupsAt('tests/windows/launch.mjs').includes('control'));
  assert.ok(groupsAt('tests/windows/testisp/harness.mjs').includes('testisp'));
  assert.ok(groupsAt('tests/linux/engine/singbox/config.mjs').includes('acceptance'), 'driver_linux.go runs config.mjs');
  assert.ok(groupsAt('lib/engine.mjs').includes('acceptance'), 'config.mjs imports lib/engine.mjs');
  assert.ok(groupsAt('tests/linux/suite/snap-inputs.json').includes('acceptance'), 'go:embed and the workflow');
  assert.ok(groupsAt('lib/lines.mjs').includes('go_linux'), 'the differential oracle runs on Linux');
  assert.ok(!groupsAt('lib/lines.mjs').includes('go_windows'), 'its step is Linux-only');
  assert.ok(groupsAt('internal/platform/worker/supervisor.go').includes('control'));
  assert.ok(!groupsAt('internal/platform/worker/supervisor.go').includes('node'), 'narrowed to Control');
});

test('Go files are reached from the go commands, not from the map', () => {
  const { groupsAt, reach } = current;
  // go1-windows vets, tests and builds ./tests/... on Windows.
  assert.ok(groupsAt('tests/linux/wire/wire.go').includes('go_windows'), 'portable tests/linux Go builds on Windows');
  assert.ok(!groupsAt('tests/linux/cmd/nsaccept/main_linux.go').includes('go_windows'), 'a _linux file never builds on Windows');
  assert.ok(groupsAt('tests/linux/cmd/nsaccept/main_other.go').includes('go_windows'), '//go:build !linux builds on Windows');
  assert.ok(!groupsAt('tests/linux/cmd/nsaccept/main_other.go').includes('acceptance'), 'nor on the Linux acceptance runners');
  assert.ok(!groupsAt('tests/linux/app/app.go').includes('go_windows'), '//go:build linux');
  // Imports: the TestISP job builds ./tests/windows/testisp only.
  const testispOnly = [...reach].filter(([file, keys]) => file.startsWith('internal/') && [...keys.keys()].some(key => key.startsWith('testisp ')));
  assert.ok(testispOnly.length > 0, 'TestISP reaches internal packages through imports');
  assert.ok(groupsAt('internal/wintun/ring_windows.go').includes('wintun'));
  assert.ok(!groupsAt('internal/wintun/ring_windows.go').includes('go_linux'));
  // The Go control build imports the root package, which embeds the UI.
  assert.ok(groupsAt('assets.go').includes('control'));
  assert.ok(groupsAt('ui/app.js').includes('control'), 'assets.go embeds ui/app.js');
  // The QUIC fixture is its own module, reached by -C and working-directory.
  assert.ok(groupsAt('tests/quicfixture/serve.go').includes('go_windows'));
  assert.ok(groupsAt('tests/quicfixture/serve.go').includes('acceptance'));
  // The helper module, from the Linux job's working directory.
  assert.ok(groupsAt('helper/main_linux_test.go').includes('helper'));
  assert.ok(!groupsAt('helper/main_windows.go').includes('helper'), 'the helper job runs on Linux');
});

test('every Go file outside generated trees that builds on Windows or Linux is compiled by some gated job', () => {
  // A go command the guard stopped parsing would otherwise reach nothing.
  const repo = repoView();
  const builds = file => ['windows', 'linux'].some(goos => nameHolds(file.split('/').at(-1), goos) && ((line => line === null || constraintHolds(line, goos))(buildLine(repo.read(file)))));
  const missing = repo.tracked.filter(file => file.endsWith('.go') && !/^(?:vendor|third_party|dist)\//.test(file) && builds(file) && !current.reach.has(file));
  assert.deepEqual(missing, []);
  // bind_other.go is //go:build !linux && !windows: no runner builds it.
  assert.ok(!current.reach.has('tests/quicfixture/bind_other.go'));
});

const fails = (options, pattern) => {
  const { problems } = driftProblems(options);
  assert.ok(problems.some(problem => pattern.test(problem)), `${pattern} not in:\n${problems.join('\n')}`);
};
const mapped = (path, area) => file => file === path ? area : areaFor(file);
const without = (area, group) => ({ ...areas, [area]: areas[area].filter(item => item !== group) });
const edit = (path, change) => ({ [path]: change(repoView().read(path)) });

test('a map that misses a reader fails the drift check', () => {
  // The exception this guard replaced: Node reads this Go source.
  fails({ areaOf: mapped('internal/control/http.go', 'go_shared') }, /^internal\/control\/http\.go .* node job/);
  fails({ areaOf: mapped('tests/windows/launch.mjs', 'tests_linux') }, /^tests\/windows\/launch\.mjs .* (node|control) job/);
  fails({ areaOf: mapped('tests/linux/engine/singbox/config.mjs', 'go_windows') }, /config\.mjs .* acceptance job/);
  fails({ groupsOf: without('frozen', 'acceptance') }, /^lib\/engine\.mjs .* acceptance job/);
  fails({ groupsOf: without('tests_linux', 'acceptance') }, /^tests\/linux\/suite\/snap-inputs\.json .* acceptance job/);
});

test('a map that misses a Go build fails, whatever the map says about Go', () => {
  // Round 2's guard seeded Go from this map, so this passed with zero errors.
  fails({ groupsOf: without('tests_linux', 'go_windows') }, /^tests\/linux\/wire\/wire\.go \(area tests_linux\) .*go1-windows.* go_windows job/);
  // Reached only through imports from ./tests/windows/testisp.
  fails({ groupsOf: without('go_shared', 'testisp') }, /^internal\/\S+\.go \(area go_shared\) .*ci\.yml testisp.* imports .* testisp job/);
  // A Windows-only file in the Wintun package, from the job's go test -c.
  fails({ groupsOf: without('go_windows', 'wintun') }, /^internal\/wintun\/\S+_windows\.go .* wintun job/);
  // A file that only a build tag keeps on Windows.
  fails({ areaOf: mapped('tests/linux/cmd/nsaccept/main_other.go', 'go_linux') }, /main_other\.go \(area go_linux\) .* go_windows job/);
});

test('embeds are expanded the way Go does, and fail when they match nothing', () => {
  const ring = 'internal/wintun/ring_windows.go';
  const embed = line => edit(ring, text => text.replace(/^package wintun$/m, `package wintun\n\nimport _ "embed"\n\n${line}\nvar embedded string`));
  // The reviewer's case. It matches the package's README.md, a docs-area
  // file, which would make Wintun's inputs skip Wintun.
  fails({ overrides: embed('//go:embed *.md') }, /^internal\/wintun\/README\.md \(area docs\) is read by internal\/wintun\/ring_windows\.go, which a wintun job runs/);
  // A glob that matches nothing fails, as it does in Go.
  fails({ overrides: embed('//go:embed *.txt') }, /ring_windows\.go: \/\/go:embed \*\.txt: no matching files found/);
  // A directory: its files, but not hidden or underscore ones without all:.
  const tree = { 'internal/wintun/guide/a.md': 'x', 'internal/wintun/guide/_b.md': 'x', 'internal/wintun/guide/.c.md': 'x' };
  const directory = driftProblems({ overrides: { ...embed('//go:embed guide'), ...tree } });
  assert.ok(directory.problems.some(problem => /^internal\/wintun\/guide\/a\.md .* wintun job/.test(problem)), directory.problems.join('\n'));
  assert.ok(!directory.problems.some(problem => /guide\/[_.]/.test(problem)), 'hidden files skipped');
  fails({ overrides: { ...embed('//go:embed all:guide'), ...tree } }, /^internal\/wintun\/guide\/_b\.md .* wintun job/);
  fails({ overrides: { ...embed('//go:embed "guide"'), 'internal/wintun/guide/_only.md': 'x' } }, /\/\/go:embed guide: cannot embed directory guide: contains no embeddable files/);
  // Patterns Go rejects.
  fails({ overrides: embed('//go:embed ../README.md') }, /\/\/go:embed \.\.\/README\.md: invalid pattern syntax/);
  fails({ overrides: embed('//go:embed "unterminated') }, /ring_windows\.go: \/\/go:embed: unterminated quote/);
  fails({ overrides: embed('//go:embed [z-a') }, /invalid pattern syntax/);
});

test('reader forms the guard can not resolve fail unless declared', () => {
  // A module imported by a computed name.
  fails({ overrides: edit('tests/windows/launch.mjs', text => `${text}\nexport const late = name => import(name);\n`) }, /^tests\/windows\/launch\.mjs: computed import import\(name\)/);
  // A computed go package, script or test folder in a workflow.
  const ci = '.github/workflows/ci.yml';
  fails({ overrides: edit(ci, text => text.replace('go build -o dist/windows-test/udpreject.exe ./tests/windows/udpreject', 'go build -o dist/windows-test/udpreject.exe $package')) }, /windows-acceptance: computed package argument/);
  fails({ overrides: edit(ci, text => text.replace('node tests/windows/testisp/proof.mjs', 'node $proof')) }, /ci\.yml testisp: node script \$proof is computed/);
  fails({ overrides: edit(ci, text => text.replace('node tests/windows/testisp/proof.mjs', 'node tests/windows/testisp/missing.mjs')) }, /node script tests\/windows\/testisp\/missing\.mjs .* is not a tracked file/);
  fails({ overrides: edit(ci, text => text.replace('go test ./tests/windows/testisp', 'go test ./tests/windows/nothing')) }, /no Go files in tests\/windows\/nothing/);
  fails({ overrides: edit(ci, text => text.replace('go vet ./internal/...', 'go vet -unknownflag ./internal/...')) }, /unknown go vet flag -unknownflag/);
  // A declared reader that no longer matches is stale.
  fails({ overrides: edit('scripts/smoke-test-installer.ps1', text => text.replace('import(process.argv[1])', "import('./lib/engine.mjs')")) }, /stale declared reader in scripts\/smoke-test-installer\.ps1/);
});

test('folder, working-directory and -C forms are followed', () => {
  const ci = '.github/workflows/ci.yml';
  const only = (options, pattern, everything) => {
    const { problems } = driftProblems(options);
    assert.ok(problems.length > 0 && problems.every(problem => pattern.test(problem)), `${pattern}:\n${problems.join('\n')}`);
    if (everything) assert.deepEqual(everything.filter(file => !problems.some(problem => problem.startsWith(`${file} `))), []);
  };
  // node --test on a folder runs the scripts in it (and what they import),
  // not the Go files beside them.
  const folder = driftProblems({ overrides: edit(ci, text => text.replace('node tests/windows/testisp/proof.mjs', 'node --test tests/linux/engine/singbox')) }).problems;
  assert.ok(folder.some(problem => /^tests\/linux\/engine\/singbox\/config\.mjs \(area tests_linux\) is read by ci\.yml testisp,/.test(problem)), folder.join('\n'));
  assert.ok(folder.some(problem => /^lib\/engine\.mjs \(area frozen\) is read by tests\/linux\/engine\/singbox\/config\.mjs, which a testisp job/.test(problem)));
  assert.ok(!folder.some(problem => /^tests\/linux\/engine\/singbox\/\S+\.go /.test(problem)), folder.join('\n'));
  fails({ overrides: edit(ci, text => text.replace('node tests/windows/testisp/proof.mjs', 'node --test tests/linux/wire')) }, /node test argument tests\/linux\/wire has no scripts under it/);
  // The helper job's "go vet ./..." runs in its working directory. Moved to a
  // shared Go package, it reaches that package's tree and nothing else.
  const packet = repoView().tracked.filter(file => /^internal\/engine\/packet\/[^/]+\.go$/.test(file) && !/_windows/.test(file));
  only({ overrides: edit(ci, text => text.replace('        working-directory: helper\n', '        working-directory: internal/engine/packet\n')) },
    /^internal\/engine\/packet\/\S+ \(area go_shared\) is read by ci\.yml linux-helper: go (vet|test|build) \.\/\.\.\. .* helper job/, packet);
  // go -C changes the directory too, relative to the working directory.
  only({ overrides: edit(ci, text => text.replace('      - run: go vet ./...\n', '      - run: go -C ../internal/engine/packet vet ./...\n')) },
    /^internal\/engine\/packet\/\S+ \(area go_shared\) is read by ci\.yml linux-helper: go -C \.\.\/internal\/engine\/packet vet \.\/\.\.\. .* helper job/, packet);
});
