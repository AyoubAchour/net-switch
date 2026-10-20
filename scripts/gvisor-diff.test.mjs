import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import test from 'node:test';

const root = fileURLToPath(new URL('../', import.meta.url));

function diff(env) {
  const result = spawnSync(process.execPath, ['scripts/generate-gvisor.mjs', '--diff'], {
    cwd: root, env, encoding: 'utf8', windowsHide: true,
  });
  assert.equal(result.status, 0, result.error?.message || result.stderr);
  assert.match(result.stdout, /^diff --git a\/pkg\//);
  return result.stdout;
}

test('gVisor patch keeps apply -p1 format under custom diff settings', () => {
  const expected = diff(process.env);
  assert.match(expected, /new file mode 100644\n[\s\S]*dispatcher_netswitch_test\.go/);
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
  const actual = diff(env);
  assert.equal(actual, expected);
  // The generated tree already contains the patch, so reverse-check it.
  const apply = spawnSync('git', ['apply', '--check', '--reverse', '-p1', '-'], {
    cwd: fileURLToPath(new URL('../third_party/gvisor/', import.meta.url)),
    env, input: actual, encoding: 'utf8', windowsHide: true,
  });
  assert.equal(apply.status, 0, apply.error?.message || apply.stderr);
});
