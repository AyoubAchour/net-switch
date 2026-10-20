import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { readFileSync, readdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import test from 'node:test';

const root = fileURLToPath(new URL('../', import.meta.url));

const patches = readdirSync(new URL('../third_party/', import.meta.url))
  .filter(name => /^gvisor-.*\.patch$/.test(name)).sort();

function diff(patch, env) {
  const result = spawnSync(process.execPath, ['scripts/generate-gvisor.mjs', '--diff', patch], {
    cwd: root, env, encoding: 'utf8', windowsHide: true,
  });
  assert.equal(result.status, 0, result.error?.message || result.stderr);
  assert.match(result.stdout, /^diff --git a\/pkg\//);
  return result.stdout;
}

for (const patch of patches) test(`${patch} regenerates byte for byte under custom diff settings`, () => {
  const expected = diff(patch, process.env);
  // Also serves as CI's canonical patch check, including file order and hashes.
  assert.equal(expected, readFileSync(new URL(`../third_party/${patch}`, import.meta.url), 'utf8').replaceAll('\r\n', '\n'));
  if (patch === 'gvisor-local-close.patch') {
    assert.match(expected, /new file mode 100644\n[\s\S]*dispatcher_netswitch_test\.go/);
    assert.match(expected, /Net Switch addition, not upstream/);
    assert.doesNotMatch(expected, /RTORecovery/);
  } else if (patch === 'gvisor-rto-recovery.patch') {
    assert.match(expected, /RTORecovery/);
    assert.doesNotMatch(expected, /dispatcher_netswitch_test|localCloseEnabled/);
  }
  const settings = {
    'diff.noprefix': 'true',
    'diff.mnemonicPrefix': 'true',
    'diff.srcPrefix': 'before/',
    'diff.dstPrefix': 'after/',
    'diff.suppressBlankEmpty': 'true',
    'diff.external': 'nonexistent-diff-command',
    'diff.context': '0',
    'diff.interHunkContext': '100',
    'diff.algorithm': 'histogram',
    'diff.indentHeuristic': 'false',
    'color.diff': 'always',
    'core.abbrev': '12',
  };
  const env = { ...process.env, GIT_CONFIG_COUNT: String(Object.keys(settings).length) };
  Object.entries(settings).forEach(([key, value], i) => {
    env[`GIT_CONFIG_KEY_${i}`] = key;
    env[`GIT_CONFIG_VALUE_${i}`] = value;
  });
  const actual = diff(patch, env);
  assert.equal(actual, expected);
  // The generated tree already contains the patch, so reverse-check it.
  const apply = spawnSync('git', ['apply', '--check', '--reverse', '-p1', '-'], {
    cwd: fileURLToPath(new URL('../third_party/gvisor/', import.meta.url)),
    env, input: actual, encoding: 'utf8', windowsHide: true,
  });
  assert.equal(apply.status, 0, apply.error?.message || apply.stderr);
});

test('diff mode requires one named patch instead of silently combining patches', () => {
  assert.deepEqual(patches, ['gvisor-local-close.patch', 'gvisor-rto-recovery.patch']);
  for (const args of [['--diff'], ['--diff', '../gvisor-local-close.patch'], ['--diff', 'missing.patch']]) {
    const result = spawnSync(process.execPath, ['scripts/generate-gvisor.mjs', ...args], {
      cwd: root, encoding: 'utf8', windowsHide: true,
    });
    assert.equal(result.status, 1);
    assert.match(result.stderr, /Usage: generate-gvisor\.mjs/);
  }
});
