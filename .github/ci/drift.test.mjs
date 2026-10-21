import assert from 'node:assert/strict';
import { test } from 'node:test';
import { areaFor, areas } from './changes.mjs';
import { declarationProblems, declared, driftProblems } from './drift.mjs';
import { buildLine, constraintHolds, nameHolds } from './golist.mjs';
import { HOLE, Reader, locate, sites } from './readers.mjs';
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
  assert.ok(groupsAt('lib/engine.mjs').includes('testisp'), 'the TestISP proof reaches lib/engine.mjs through local-traffic.mjs');
  assert.ok(groupsAt('tests/linux/engine/singbox/config.mjs').includes('acceptance'), 'driver_linux.go runs config.mjs');
  assert.ok(groupsAt('lib/engine.mjs').includes('acceptance'), 'config.mjs imports lib/engine.mjs');
  assert.ok(groupsAt('tests/linux/suite/snap-inputs.json').includes('acceptance'), 'go:embed and the workflow');
  assert.ok(groupsAt('lib/lines.mjs').includes('go_linux'), 'the differential oracle runs on Linux');
  assert.ok(!groupsAt('lib/lines.mjs').includes('go_windows'), 'its step is Linux-only');
  assert.ok(groupsAt('internal/platform/worker/supervisor.go').includes('control'));
  assert.ok(!groupsAt('internal/platform/worker/supervisor.go').includes('node'), 'narrowed to Control');
  // Computed paths the evaluator places: a template under internal/, a
  // URL joined onto a folder URL, and a computed name under the reader.
  assert.ok(groupsAt('internal/apps/node-tests.json').includes('node'), 'pure-port-fixtures.test.mjs reads internal/${name}/node-tests.json');
  assert.ok(groupsAt('tests/oracle/fixtures/combining.trace.json').includes('node'), 'traces.test.mjs reads new URL(name, dir)');
  assert.ok(groupsAt('test/fixtures/windows-golden.json').includes('go_windows'), 'config_test.go reads the golden configs');
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

test('the go commands the oracle checks come from the workflows', () => {
  // golist-check.mjs runs go list for exactly these; a parsing change that
  // loses one would shrink what the oracle compares.
  const settings = new Set(current.go.map(command => [command.os, command.runner, command.dir || '.', command.tags.join(','), command.race ? 'race' : ''].filter(Boolean).join(' ')));
  const has = pattern => [...settings].some(setting => pattern.test(setting));
  assert.ok(has(/^Windows windows-latest \. control_test_https$/), 'Control builds ./cmd/netswitch with -tags control_test_https');
  assert.ok(has(/^Windows windows-11-arm \. control_test_https$/));
  assert.ok(has(/^Linux ubuntu-24\.04-arm \.$/), 'go1-linux on ARM64');
  assert.ok(has(/^Windows windows-latest \. race$/), 'race builds on Windows x64');
  assert.ok(!has(/^Windows windows-11-arm \. race$/), 'not on Windows ARM64');
  assert.ok(has(/^Linux ubuntu-24\.04 helper$/), 'the helper module from its working directory');
  assert.ok(has(/^Linux ubuntu-26\.04 tests\/quicfixture$/), 'the QUIC fixture on every acceptance runner');
  assert.ok(current.go.some(command => command.group === 'control' && command.patterns.includes('./cmd/netswitch')));
});

const fails = (options, pattern) => {
  const { problems } = driftProblems(options);
  assert.ok(problems.some(problem => pattern.test(problem)), `${pattern} not in:\n${problems.join('\n')}`);
};
const mapped = (path, area) => (file, tracked) => file === path ? area : areaFor(file, tracked);
const without = (area, group) => name => [...new Set(name.split('+').flatMap(part => part === area ? areas[part].filter(item => item !== group) : areas[part]))];
const edit = (path, change) => ({ [path]: change(repoView().read(path)) });

test('a map that misses a reader fails the drift check', () => {
  // The exception this guard replaced: Node reads this Go source.
  fails({ areaOf: mapped('internal/control/http.go', 'go_shared') }, /^internal\/control\/http\.go .* node job/);
  fails({ areaOf: mapped('tests/windows/launch.mjs', 'tests_linux') }, /^tests\/windows\/launch\.mjs .* (node|control) job/);
  fails({ areaOf: mapped('tests/linux/engine/singbox/config.mjs', 'go_windows') }, /config\.mjs .* acceptance job/);
  fails({ groupsOf: without('frozen', 'acceptance') }, /^lib\/engine\.mjs .* acceptance job/);
  fails({ groupsOf: without('frozen', 'testisp') }, /^lib\/engine\.mjs .* testisp job/);
  fails({ groupsOf: without('tests_linux', 'acceptance') }, /^tests\/linux\/suite\/snap-inputs\.json .* acceptance job/);
  // docs/ looks like documentation, but the installer ships all of it.
  fails({ areaOf: (file, tracked) => file.startsWith('docs/') ? 'docs' : areaFor(file, tracked) }, /^docs\/user-guide\.md \(area docs\) is read by scripts\/build-release\.ps1, which a installer job/);
  // Fixtures beside Go code that a Node test reads.
  fails({ areaOf: mapped('internal/apps/node-tests.json', 'go_shared') }, /^internal\/apps\/node-tests\.json \(area go_shared\) is read by test\/pure-port-fixtures\.test\.mjs, which a node job/);
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
  // Round 3's case: //go:embed *.md matches the package's README.md. The
  // locality rule now makes that README Wintun's input, so the real map
  // passes; a map that calls it documentation still fails.
  assert.deepEqual(driftProblems({ overrides: embed('//go:embed *.md') }).problems, []);
  fails({ overrides: embed('//go:embed *.md'), areaOf: mapped('internal/wintun/README.md', 'docs') }, /^internal\/wintun\/README\.md \(area docs\) is read by internal\/wintun\/ring_windows\.go, which a wintun job runs/);
  // A glob that matches nothing fails, as it does in Go.
  fails({ overrides: embed('//go:embed *.txt') }, /ring_windows\.go: \/\/go:embed \*\.txt: no matching files found/);
  // A directory: its files, but not hidden or underscore ones without all:.
  const tree = { 'internal/wintun/guide/a.md': 'x', 'internal/wintun/guide/_b.md': 'x', 'internal/wintun/guide/.c.md': 'x' };
  const asDocs = (file, tracked) => file.startsWith('internal/wintun/guide/') ? 'docs' : areaFor(file, tracked);
  // (The TestISP program's "internal/wintun" string reads the whole folder
  // as well, so only what ring_windows.go reads counts here.)
  const embedded = options => driftProblems(options).problems.filter(problem => problem.includes('is read by internal/wintun/ring_windows.go,'));
  const directory = embedded({ overrides: { ...embed('//go:embed guide'), ...tree }, areaOf: asDocs });
  assert.ok(directory.some(problem => /^internal\/wintun\/guide\/a\.md .* wintun job/.test(problem)), directory.join('\n'));
  assert.ok(!directory.some(problem => /guide\/[_.]/.test(problem)), 'hidden files skipped');
  assert.ok(embedded({ overrides: { ...embed('//go:embed all:guide'), ...tree }, areaOf: asDocs }).some(problem => /^internal\/wintun\/guide\/_b\.md .* wintun job/.test(problem)));
  fails({ overrides: { ...embed('//go:embed "guide"'), 'internal/wintun/guide/_only.md': 'x' } }, /\/\/go:embed guide: cannot embed directory guide: contains no embeddable files/);
  // Patterns Go rejects.
  fails({ overrides: embed('//go:embed ../README.md') }, /\/\/go:embed \.\.\/README\.md: invalid pattern syntax/);
  fails({ overrides: embed('//go:embed "unterminated') }, /ring_windows\.go: \/\/go:embed: unterminated quote/);
  fails({ overrides: embed('//go:embed [z-a') }, /invalid pattern syntax/);
});

// ---- Computed readers (readers.mjs).

const ringTest = 'internal/wintun/ring_windows_test.go';
const addGoTest = body => edit(ringTest, text => `${text}\n${body}\n`);

test("the reviewer's Go case: a Windows test reads outside its folder through a variable", () => {
  fails({ overrides: addGoTest('func TestReadsTheRootReadme(t *testing.T) {\n\tname := "../../README.md"\n\tif _, err := os.ReadFile(name); err != nil {\n\t\tt.Fatal(err)\n\t}\n}') },
    /^README\.md \(area docs\) is read by internal\/wintun\/ring_windows_test\.go, which a (wintun|go_windows) job runs/);
  // The same name handed to a helper as an argument: the literal counts.
  fails({ overrides: addGoTest('func readNamed(t *testing.T, name string) []byte {\n\tb, _ := os.ReadFile(name)\n\treturn b\n}\n\nfunc TestHelper(t *testing.T) { readNamed(t, "../../README.md") }') },
    /^README\.md \(area docs\) is read by internal\/wintun\/ring_windows_test\.go/);
  // Climbing from a parameter with '..', or past a computed name.
  fails({ overrides: addGoTest('func readUp(dir string) { os.ReadFile(filepath.Join(dir, "..", "..", "README.md")) }') },
    /ring_windows_test\.go:\d+: os\.ReadFile\(filepath\.Join\(dir, "\.\.", "\.\.", "README\.md"\)\): climbs with '\.\.' from a parameter/);
  fails({ overrides: addGoTest('func readSibling(name string) { os.ReadFile(filepath.Join("..", name, "..", "..", "README.md")) }') },
    /climbs above the fixed part of a computed path/);
  // A name read beside the test is the package's own input: allowed, and
  // the file it can reach selects the test's jobs by the locality rule.
  const local = driftProblems({ overrides: { ...addGoTest('func readLocal(name string) { os.ReadFile(filepath.Join("testdata", name)) }'), 'internal/wintun/testdata/frame.bin': 'x' } });
  assert.deepEqual(local.problems, []);
  assert.ok(local.groupsAt('internal/wintun/testdata/frame.bin').includes('wintun'), 'followed as everything under testdata');
});

test("the reviewer's PowerShell case: Get-ChildItem from the script's parent folder", () => {
  const script = 'scripts/prepare-wintun-tests.ps1';
  fails({ overrides: edit(script, text => `${text}\nGet-ChildItem -Path (Join-Path $PSScriptRoot "..") -Filter *.md -Recurse | Get-Content\n`) },
    /^scripts\/prepare-wintun-tests\.ps1:\d+: Get-ChildItem\(\(Join-Path \$PSScriptRoot "\.\."\)\): lists the whole repository/);
  // One folder lower it is followed: every file under tests/ reaches the
  // Wintun jobs, and the map doesn't select them there.
  fails({ overrides: edit(script, text => `${text}\nGet-ChildItem -Path (Join-Path $PSScriptRoot "../tests/windows") -Filter *.md -Recurse | Get-Content\n`) },
    /^tests\/windows\/README\.md \(area tests_windows\) is read by scripts\/prepare-wintun-tests\.ps1, which a wintun job runs/);
  // A path from a computed name on the repository root, and from a variable
  // the script never sets.
  fails({ overrides: edit(script, text => `${text}\n$name = $args[0]\nGet-Content (Join-Path $PSScriptRoot "../$name")\n`) }, /prepare-wintun-tests\.ps1:\d+: .*a computed part directly on the repository root/);
  fails({ overrides: edit(script, text => `${text}\nGet-Content $env:REVIEW_INPUT\n`) }, /prepare-wintun-tests\.ps1:\d+: Get-Content\(\$env:REVIEW_INPUT\): reads a path from environment variable REVIEW_INPUT/);
});

test("the reviewer's workflow case: a step runs a computed executable", () => {
  const ci = '.github/workflows/ci.yml';
  const step = '      - name: Run the 1.0 profile against the real Windows engine\n';
  // A renamed step would make every replace below a silent no-op.
  assert.ok(repoView().read(ci).includes(step), `ci.yml has no step ${JSON.stringify(step)}`);
  fails({ overrides: edit(ci, text => text.replace(step, `      - run: '& $env:REVIEW_SCRIPT'\n${step}`)) }, /ci\.yml windows-acceptance: step \d+: computed executable &\(\$env:REVIEW_SCRIPT\)/);
  fails({ overrides: edit(ci, text => text.replace(step, `      - run: '& $script'\n${step}`)) }, /ci\.yml windows-acceptance: step \d+: computed executable &\(\$script\)/);
  // A POSIX shell: the first word of a command.
  fails({ overrides: edit(ci, text => text.replace('      - run: go vet ./...\n', '      - run: \'"$REVIEW" --check\'\n      - run: go vet ./...\n')) }, /ci\.yml linux-helper: computed executable \$REVIEW/);
  // What the job built itself runs fine: linux-acceptance.yml runs
  // "$RUNNER_TEMP/nsaccept", built by go build -o "$RUNNER_TEMP/nsaccept".
  assert.ok(!current.problems.some(problem => /nsaccept/.test(problem)));
  fails({ overrides: edit('.github/workflows/linux-acceptance.yml', text => text.replace('-o "$RUNNER_TEMP/nsaccept"', '-o "$RUNNER_TEMP/other"')) }, /linux-acceptance\.yml linux: computed executable \$RUNNER_TEMP\/nsaccept/);
});

test('other computed reader forms fail unless declared', () => {
  // A module imported by a computed name.
  fails({ overrides: edit('tests/windows/launch.mjs', text => `${text}\nexport const late = name => import(name);\n`) }, /^tests\/windows\/launch\.mjs: computed import import\(name\)/);
  // A script path from a computed name under the repository root.
  fails({ overrides: edit('tests/windows/launch.mjs', text => `${text}\nexport const source = name => readFile(path.join(repoRoot, name), 'utf8');\n`) },
    /^tests\/windows\/launch\.mjs:\d+: readFile\(path\.join\(repoRoot, name\)\): a computed part directly on the repository root/);
  fails({ overrides: edit('tests/windows/launch.mjs', text => `${text}\nexport const fromArgument = () => readFile(process.argv[2], 'utf8');\n`) }, /readFile\(process\.argv\[2\]\): reads a path from argument/);
  // A computed go package, script or test folder in a workflow.
  const ci = '.github/workflows/ci.yml';
  fails({ overrides: edit(ci, text => text.replace('go build -o dist/windows-test/udpreject.exe ./tests/windows/udpreject', 'go build -o dist/windows-test/udpreject.exe $package')) }, /windows-acceptance: computed package argument/);
  fails({ overrides: edit(ci, text => text.replace('node tests/windows/testisp/proof.mjs', 'node $proof')) }, /ci\.yml testisp: node script \$proof is computed/);
  fails({ overrides: edit(ci, text => text.replace('node tests/windows/testisp/proof.mjs', 'node tests/windows/testisp/missing.mjs')) }, /node script tests\/windows\/testisp\/missing\.mjs .* is not a tracked file/);
  fails({ overrides: edit(ci, text => text.replace('go test ./tests/windows/testisp', 'go test ./tests/windows/nothing')) }, /no Go files in tests\/windows\/nothing/);
  fails({ overrides: edit(ci, text => text.replace('go vet ./internal/...', 'go vet -unknownflag ./internal/...')) }, /unknown go vet flag -unknownflag/);
});

test('declarations need a reason, a call site and what they read, and match per call site', () => {
  const repo = repoView();
  assert.deepEqual(declarationProblems(repo), []);
  const entry = declared.find(item => item.from === 'scripts/smoke-test-installer.ps1');
  const change = (patch, pattern) => {
    const saved = { ...entry };
    Object.assign(entry, patch);
    try {
      assert.ok(declarationProblems(repo).some(problem => pattern.test(problem)), pattern);
      fails({}, pattern);
    } finally {
      for (const key of Object.keys(entry)) delete entry[key];
      Object.assign(entry, saved);
    }
  };
  change({ why: '' }, /declared reader scripts\/smoke-test-installer\.ps1 import\(process\.argv\[1\]\): no reason given/);
  change({ why: '   ' }, /no reason given/);
  change({ reads: [] }, /needs either the repository paths it reads or where outside the repository it points, not neither/);
  change({ outside: 'somewhere' }, /not both/);
  change({ reads: ['lib/missing.mjs'] }, /lib\/missing\.mjs is not a tracked file or folder/);
  change({ from: 'scripts/missing.ps1' }, /scripts\/missing\.ps1 is not a tracked file/);
  // A declaration that no longer matches its call site is stale, and the
  // site it used to cover fails again.
  fails({ overrides: edit('scripts/smoke-test-installer.ps1', text => text.replace('import(process.argv[1])', 'import(process.argv[2])')) }, /stale declared reader in scripts\/smoke-test-installer\.ps1: import\(process\.argv\[1\]\) matches 0 call sites/);
  fails({ overrides: edit('scripts/smoke-test-installer.ps1', text => text.replace('import(process.argv[1])', 'import(process.argv[2])')) }, /computed import import\(process\.argv\[2\]\)/);
  // A second site with the same call is not covered by the first's entry.
  fails({ overrides: edit('scripts/smoke-test-installer.ps1', text => text.replace('$check = "const { Engine } = await import(process.argv[1]);', '$check = "const { Engine } = await import(process.argv[1]); await import(process.argv[1]);')) },
    /miscounted declared reader in scripts\/smoke-test-installer\.ps1: import\(process\.argv\[1\]\) matches 2 call sites, declared 1/);
  // Another computed import on the declared line is its own call site.
  fails({ overrides: edit('scripts/smoke-test-installer.ps1', text => text.replace('await import(process.argv[1]);', 'await import(process.argv[1]); await import(process.env.OTHER);')) }, /computed import import\(process\.env\.OTHER\)/);
});

test('the evaluator places the path forms it accepts', () => {
  const repo = repoView();
  const at = (file, text, lang) => {
    const reader = new Reader(repo, file, { text, lang });
    return sites(reader).map(site => ({ key: site.key, where: site.values.map(item => locate(repo, item, reader)) }));
  };
  // The one read, list or run site in the snippet.
  const only = (file, text, lang) => {
    const found = at(file, text, lang).filter(site => !/^(?:new URL|path\.join|filepath\.Join|\(Join-Path)/.test(site.key));
    assert.equal(found.length, 1, JSON.stringify(found));
    return found[0].where;
  };
  // Literal, through a variable, a URL and a template.
  assert.deepEqual(only('test/x.test.mjs', "import { readFile } from 'node:fs/promises';\nconst p = new URL('../package.json', import.meta.url);\nawait readFile(p);\n")[0].files, ['package.json']);
  assert.ok(only('test/x.test.mjs', "import { readFile } from 'node:fs/promises';\nconst f = n => readFile(new URL(`../internal/${n}/node-tests.json`, import.meta.url));\n")[0].files.includes('internal/apps/node-tests.json'));
  // Temporary folders are outside the repository.
  assert.ok(only('test/x.test.mjs', "import { readFile, mkdtemp } from 'node:fs/promises';\nimport os from 'node:os';\nconst dir = await mkdtemp(os.tmpdir());\nawait readFile(dir);\n")[0].outside);
  assert.ok(only('internal/wintun/x_test.go', 'package wintun\nfunc T(t *testing.T) {\n\tdir := t.TempDir()\n\tos.ReadFile(filepath.Join(dir, "x"))\n}\n', 'go')[0].outside);
  // A loop over a literal list, in PowerShell, sees only its own binding.
  const loop = at('scripts/x.ps1', "$repoRoot = Join-Path $PSScriptRoot '..'\nforeach ($name in @('package.json', 'LICENSE')) { Test-Path (Join-Path $repoRoot $name) }\nforeach ($f in $files) { $name = $f.Name }\n", 'ps');
  assert.deepEqual(loop.find(site => site.key.startsWith('Test-Path')).where.flatMap(where => where.files), ['package.json', 'LICENSE']);
  // A computed name under the reader's folder: everything below it.
  const below = only('tests/windows/x.mjs', "import { readFile } from 'node:fs/promises';\nimport path from 'node:path';\nconst here = import.meta.dirname;\nexport const read = name => readFile(path.join(here, 'testisp', name));\n")[0];
  assert.ok(below.pattern && below.files.includes('tests/windows/testisp/harness.mjs'), JSON.stringify(below));
  assert.equal(HOLE, '\0');
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
