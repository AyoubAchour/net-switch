import assert from 'node:assert/strict';
import { test } from 'node:test';
import { GoTree, buildLine, constraintHolds, goCommand, matchRegExp, nameHolds } from './golist.mjs';
import { generated, repoView } from './repo.mjs';

// The Go rules golist.mjs reimplements, case by case, on small in-memory
// trees. golist-check.mjs compares the whole selection with go list in CI.

const module = 'github.com/AyoubAchour/net-switch';
const treeOf = files => new GoTree(repoView(files), { skip: path => generated.test(path) });

test('file names constrain GOOS and architecture the way go/build does', () => {
  assert.equal(nameHolds('ring_windows.go', 'windows'), true);
  assert.equal(nameHolds('ring_windows.go', 'linux'), false);
  assert.equal(nameHolds('ring_windows_test.go', 'linux'), false);
  assert.equal(nameHolds('main_linux_test.go', 'linux'), true);
  assert.equal(nameHolds('sys_windows_arm64.go', 'windows'), true);
  assert.equal(nameHolds('sys_linux_386.go', 'linux'), false, 'no runner is 386');
  assert.equal(nameHolds('sys_amd64.go', 'windows'), true);
  assert.equal(nameHolds('linux.go', 'windows'), true, 'only after the first underscore');
  assert.equal(nameHolds('x_unix.go', 'windows'), true, 'unix is not a file-name tag');
  assert.equal(nameHolds('a_darwin.go', 'linux'), false);
});

test('//go:build lines hold when some open tag setting compiles the file', () => {
  assert.equal(constraintHolds('windows', 'windows'), true);
  assert.equal(constraintHolds('!windows', 'windows'), false);
  assert.equal(constraintHolds('!linux && !windows', 'linux'), false);
  assert.equal(constraintHolds('!linux && !windows', 'windows'), false);
  assert.equal(constraintHolds('unix', 'linux'), true);
  assert.equal(constraintHolds('unix', 'windows'), false);
  assert.equal(constraintHolds('linux && (amd64 || arm64)', 'linux'), true);
  assert.equal(constraintHolds('linux && 386', 'linux'), false);
  // One architecture per build: CI runs amd64 and arm64, never neither.
  assert.equal(constraintHolds('linux && !amd64 && !arm64', 'linux'), false);
  assert.equal(constraintHolds('linux && !amd64', 'linux'), true, 'arm64');
  assert.equal(constraintHolds('amd64 && arm64', 'linux'), false);
  assert.equal(constraintHolds('amd64 || arm64', 'linux'), true);
  assert.equal(constraintHolds('close_fence_disabled', 'linux'), true, 'custom tags are open');
  assert.equal(constraintHolds('!close_fence_disabled', 'linux'), true);
  assert.equal(constraintHolds('tag && !tag', 'linux'), false);
  assert.throws(() => constraintHolds('linux &&', 'linux'), /Unsupported/);
});

test('exact settings decide every tag, the way go list sees one command', () => {
  const control = { goarch: 'arm64', tags: new Set(['control_test_https']) };
  assert.equal(constraintHolds('control_test_https', 'windows', control), true);
  assert.equal(constraintHolds('!control_test_https', 'windows', control), false);
  assert.equal(constraintHolds('!close_fence_disabled', 'windows', control), true, 'an unnamed tag is off');
  assert.equal(constraintHolds('close_fence_disabled', 'windows', control), false);
  assert.equal(constraintHolds('linux && amd64', 'linux', control), false, 'the architecture is the runner\'s');
  assert.equal(constraintHolds('race', 'linux', { goarch: 'amd64', tags: new Set(['race']) }), true, '-race sets race');
  assert.equal(constraintHolds('gc && !gccgo', 'linux', control), true);
  assert.equal(nameHolds('sys_amd64.go', 'windows', control), false);
  assert.equal(nameHolds('sys_arm64.go', 'windows', control), true);
  assert.throws(() => constraintHolds('go1.30', 'linux', control), /release tag go1\.30 isn't modelled/);
  const tree = treeOf({
    'zz/c/files.go': '//go:build !control_test_https\n\npackage c\n', 'zz/c/fixture.go': '//go:build control_test_https\n\npackage c\n',
    'zz/c/c_amd64.go': 'package c\n',
  });
  assert.deepEqual([...tree.load(['zz/c'], 'windows', false, control).keys()].sort(), ['zz/c/fixture.go']);
  assert.deepEqual([...tree.load(['zz/c'], 'windows', false).keys()].sort(), ['zz/c/c_amd64.go', 'zz/c/files.go', 'zz/c/fixture.go'], 'open: every setting');
});

test('only the header before the package clause carries //go:build', () => {
  assert.equal(buildLine('// Copyright\n\n//go:build windows\n\npackage x\n'), 'windows');
  assert.equal(buildLine('/* block\n comment */\n//go:build linux\npackage x\n'), 'linux');
  assert.equal(buildLine('package x\n\n//go:build windows\n'), null);
  assert.throws(() => buildLine('// +build windows\n\npackage x\n'), /\+build without/);
});

test('"./..." walks the module the way the go command does', () => {
  const tree = treeOf({
    'zz/a/a.go': 'package a\n', 'zz/a/b/b.go': 'package b\n', 'zz/a/testdata/t.go': 'package t\n',
    'zz/a/_x/x.go': 'package x\n', 'zz/a/.y/y.go': 'package y\n', 'zz/a/vendor/v.go': 'package v\n',
    'zz/a/mod/go.mod': 'module example.com/mod\n', 'zz/a/mod/m.go': 'package m\n', 'zz/a/docs/README.md': 'x',
  });
  assert.deepEqual(tree.expand('./zz/a/...', '').sort(), ['zz/a', 'zz/a/b']);
  assert.deepEqual(tree.expand('./...', 'zz/a/mod'), ['zz/a/mod'], 'a nested module walks itself only');
  assert.deepEqual(tree.expand('../b', 'zz/a/docs'), ['zz/a/b']);
  assert.deepEqual(tree.expand(`${module}/zz/a/b`, ''), ['zz/a/b']);
  assert.equal(tree.expand('net/http', ''), null, 'standard library');
  assert.equal(tree.expand('gvisor.dev/gvisor/pkg/tcpip', ''), null, 'a dependency');
  assert.throws(() => tree.expand('./zz/none', ''), /no Go files/);
  assert.throws(() => tree.expand('./zz/a/docs/...', ''), /matches no packages/);
  assert.throws(() => tree.expand('zz/a', ''), /unsupported package argument/, 'a folder without ./');
  assert.throws(() => tree.expand('./zz/.../b', ''), /unsupported package pattern/);
});

test('loading follows imports in the same module, and test imports only for named packages', () => {
  const tree = treeOf({
    'zz/p/p.go': `package p\n\nimport (\n\t"fmt"\n\tq "${module}/zz/q"\n)\n`,
    'zz/p/p_windows.go': `package p\n\nimport "${module}/zz/w"\n`,
    'zz/p/p_test.go': `package p\n\nimport _ "${module}/zz/t"\n`,
    'zz/q/q.go': 'package q\n', 'zz/q/q_test.go': `package q\n\nimport "${module}/zz/never"\n`,
    'zz/w/w.go': 'package w\n', 'zz/t/t.go': 'package t\n', 'zz/never/n.go': 'package never\n',
  });
  assert.deepEqual([...tree.load(['zz/p'], 'linux', true).keys()].sort(), ['zz/p/p.go', 'zz/p/p_test.go', 'zz/q/q.go', 'zz/t/t.go']);
  assert.deepEqual([...tree.load(['zz/p'], 'windows', false).keys()].sort(), ['zz/p/p.go', 'zz/p/p_windows.go', 'zz/q/q.go', 'zz/w/w.go']);
  assert.match(tree.load(['zz/p'], 'linux', false).get('zz/q/q.go'), /zz\/p imports .*zz\/q/);
  const missing = treeOf({ 'zz/p/p.go': `package p\n\nimport "${module}/zz/gone"\n` });
  assert.throws(() => missing.load(['zz/p'], 'linux', false), /imports .*zz\/gone, which has no Go files/);
});

test('embeds follow resolveEmbed: globs, folders, hidden files and module edges', () => {
  const tree = treeOf({
    'zz/e/e.go': 'package e\n', 'zz/e/a.txt': 'x', 'zz/e/.hidden.txt': 'x', 'zz/e/sub/b.txt': 'x',
    'zz/e/dir/c.txt': 'x', 'zz/e/dir/_d.txt': 'x', 'zz/e/dir/.e/f.txt': 'x', 'zz/e/dir/inner/g.txt': 'x',
    'zz/e/dir/mod/go.mod': 'module example.com/m\n', 'zz/e/dir/mod/h.txt': 'x', 'zz/e/other/go.mod': 'module example.com/o\n', 'zz/e/other/i.txt': 'x',
  });
  const embed = pattern => tree.embedPattern('zz/e', pattern).sort();
  assert.deepEqual(embed('*.txt'), ['zz/e/.hidden.txt', 'zz/e/a.txt'], 'a glob names hidden files too; * stays in one folder');
  assert.deepEqual(embed('*/b.txt'), ['zz/e/sub/b.txt']);
  assert.deepEqual(embed('dir'), ['zz/e/dir/c.txt', 'zz/e/dir/inner/g.txt'], 'a folder skips . and _ names and nested modules');
  assert.deepEqual(embed('all:dir'), ['zz/e/dir/.e/f.txt', 'zz/e/dir/_d.txt', 'zz/e/dir/c.txt', 'zz/e/dir/inner/g.txt']);
  assert.deepEqual(embed('[ab].txt'), ['zz/e/a.txt']);
  assert.throws(() => embed('other/i.txt'), /in different module/);
  assert.throws(() => embed('missing.txt'), /no matching files found/);
  for (const bad of ['../a.txt', '/a.txt', 'a/', '.', 'sub//b.txt', '[a.txt', 'a.txt\\']) assert.throws(() => embed(bad), /invalid pattern syntax/, bad);
  const quoted = treeOf({ 'zz/e/e.go': 'package e\n\n//go:embed "a b.txt" `c.txt`\nvar x string\n', 'zz/e/a b.txt': 'x', 'zz/e/c.txt': 'x' });
  assert.deepEqual(quoted.embeds('zz/e/e.go'), { files: ['zz/e/a b.txt', 'zz/e/c.txt'], errors: [] });
});

test('path.Match classes and escapes', () => {
  assert.ok(matchRegExp('[^a]?.go').test('bx.go'));
  assert.ok(!matchRegExp('[^a]?.go').test('ax.go'));
  assert.ok(matchRegExp('\\*.go').test('*.go'));
  assert.ok(!matchRegExp('*.go').test('a/b.go'));
  assert.throws(() => matchRegExp('[]'), /bad character class/);
});

test('go commands: flags, values and package arguments', () => {
  const words = text => text.split(' ');
  assert.deepEqual(goCommand(words('go test -race -c -o ./bin/w.exe ./internal/wintun')), { chdir: null, sub: 'test', tests: true, packages: ['./internal/wintun'] });
  assert.deepEqual(goCommand(words('go -C tests/quicfixture vet ./...')), { chdir: 'tests/quicfixture', sub: 'vet', tests: true, packages: ['./...'] });
  assert.deepEqual(goCommand(words('go build -tags x -ldflags -X -o bin/n.exe ./cmd/netswitch')).packages, ['./cmd/netswitch']);
  assert.deepEqual(goCommand(words('go build -trimpath -o out')).packages, ['.']);
  assert.equal(goCommand(words('go build')).tests, false);
  assert.equal(goCommand(words('go mod verify')), null);
  assert.equal(goCommand(['go']), null);
  assert.throws(() => goCommand(words('go test -bogus ./x')), /unknown go test flag -bogus/);
  assert.throws(() => goCommand(words('go run ./x')), /unsupported go subcommand/);
});
