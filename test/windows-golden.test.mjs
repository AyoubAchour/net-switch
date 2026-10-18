import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { test } from 'node:test';
import { Engine } from '../lib/engine.mjs';
import { digest, goldenOutputs, ruleCases } from './windows-golden-cases.mjs';

const expected = JSON.parse(await readFile(new URL('./fixtures/windows-golden.json', import.meta.url), 'utf8'));

test('Windows engine configs, rules and update assets match the pre-seam outputs', () => {
  assert.deepEqual(goldenOutputs(), expected);
});

test('rule files retain their exact pre-seam bytes, including capped lines and empty sets', async () => {
  const dataDir = await mkdtemp(path.join(os.tmpdir(), 'netswitch-golden-'));
  try {
    for (const { name, options } of ruleCases()) {
      const engine = new Engine({ dataDir, mode: 'proxy', singBoxPath: 'unused' });
      await engine.changeRules(options);
      for (const [tag, hash] of Object.entries(expected[name])) {
        assert.equal(digest(await readFile(path.join(dataDir, `${tag}.json`))), hash, `${name}: ${tag}`);
      }
    }
  } finally {
    await rm(dataDir, { recursive: true, force: true });
  }
});
