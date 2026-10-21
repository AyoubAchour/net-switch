// Checks golist.mjs against the go command itself, on the root module's
// packages the Go 1.0 jobs vet, test and build. It needs Go, so go1-linux runs
// it rather than the classifier job.
//
// golist.mjs leaves the architecture and custom build tags open, so the go
// command is asked for every setting of them (amd64 and arm64, every custom
// tag off and on) and the union must equal what golist.mjs selects: no file
// missing, which would hide an input, and none extra, which would mean the
// rules here have drifted from Go's.
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { isAbsolute, posix, relative } from 'node:path';
import { GoTree, buildLine } from './golist.mjs';
import { generated, repoView } from './repo.mjs';

const patterns = ['./internal/...', './cmd/...', './tests/...'];
const root = execFileSync('git', ['rev-parse', '--show-toplevel'], { encoding: 'utf8' }).trim();
const repo = repoView();
const tree = new GoTree(repo, { skip: path => generated.test(path) });
const modulePath = tree.moduleOf('').path;
const custom = [...new Set(repo.tracked.filter(file => file.endsWith('.go') && !generated.test(file))
  .flatMap(file => (buildLine(repo.read(file)) ?? '').match(/[\w.]+/g) ?? []))]
  .filter(tag => !['linux', 'windows', 'unix', 'amd64', 'arm64'].includes(tag)).sort();
console.log(`custom tags: ${custom.join(' ') || '(none)'}`);

// go list -json writes one object after another.
const objects = text => text.trim() ? text.trim().split(/\n(?=\{)/).map(part => JSON.parse(part)) : [];

for (const goos of ['windows', 'linux']) {
  const listed = new Set();
  for (const goarch of ['amd64', 'arm64']) {
    for (const tags of [[], custom]) {
      const output = execFileSync('go', ['list', '-e', '-deps', '-test', `-tags=${tags.join(',')}`,
        '-json=ImportPath,Dir,Module,Error,GoFiles,TestGoFiles,XTestGoFiles,EmbedFiles,TestEmbedFiles,XTestEmbedFiles', ...patterns], {
        cwd: root, encoding: 'utf8', maxBuffer: 256 << 20,
        env: { ...process.env, GOOS: goos, GOARCH: goarch, CGO_ENABLED: '0', GOFLAGS: '-mod=vendor' },
      });
      for (const pkg of objects(output)) {
        if (pkg.Module?.Path !== modulePath) continue;
        assert.equal(pkg.Error, undefined, `${goos}/${goarch} ${pkg.ImportPath}: ${pkg.Error?.Err}`);
        const dir = relative(root, pkg.Dir).replace(/\\/g, '/');
        for (const name of [pkg.GoFiles, pkg.TestGoFiles, pkg.XTestGoFiles, pkg.EmbedFiles, pkg.TestEmbedFiles, pkg.XTestEmbedFiles].flat().filter(Boolean)) {
          if (isAbsolute(name)) continue; // the generated _testmain.go
          listed.add(dir ? posix.join(dir, name) : name);
        }
      }
    }
  }
  const selected = new Set();
  for (const file of tree.load(patterns.flatMap(pattern => tree.expand(pattern, '')), goos, true).keys()) {
    selected.add(file);
    const { files, errors } = tree.embeds(file);
    assert.deepEqual(errors, [], file);
    for (const embedded of files) selected.add(embedded);
  }
  const missing = [...listed].filter(file => !selected.has(file)).sort();
  const extra = [...selected].filter(file => !listed.has(file)).sort();
  assert.deepEqual(missing, [], `GOOS=${goos}: go list compiles or embeds these, golist.mjs doesn't`);
  assert.deepEqual(extra, [], `GOOS=${goos}: golist.mjs selects these, go list doesn't`);
  assert.ok(listed.size > 100, `GOOS=${goos}: only ${listed.size} files listed`);
  console.log(`GOOS=${goos}: golist.mjs and go list agree on ${listed.size} files`);
}
