import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { posix } from 'node:path';
import { fileURLToPath } from 'node:url';

// The repository as git tracks it, for drift.mjs and golist-check.mjs.

const root = fileURLToPath(new URL('../../', import.meta.url));
const baseTracked = execFileSync('git', ['ls-files', '-z'], { cwd: root, encoding: 'utf8', maxBuffer: 256 * 1024 * 1024 }).split('\0').filter(Boolean);
const baseSet = new Set(baseTracked);
const contents = new Map();

// Generated or vendored trees: the classifier treats them as shared input.
export const generated = /^(?:vendor|third_party|dist)\//;

// In-memory edits for the mutation tests: a string replaces or adds a file,
// null removes one.
export function repoView(overrides = {}) {
  const tracked = baseTracked.filter(file => overrides[file] !== null);
  for (const [file, text] of Object.entries(overrides)) if (text !== null && !baseSet.has(file)) tracked.push(file);
  tracked.sort();
  const set = new Set(tracked);
  const dirs = new Set(tracked.flatMap(file => file.split('/').slice(0, -1).map((_, index, parts) => parts.slice(0, index + 1).join('/'))));
  return {
    tracked, dirs, has: path => set.has(path),
    read(path) {
      if (Object.hasOwn(overrides, path)) {
        if (overrides[path] === null) throw new Error(`${path} was removed`);
        return overrides[path];
      }
      if (!contents.has(path)) contents.set(path, readFileSync(posix.join(root, path), 'utf8').replace(/\r\n/g, '\n'));
      return contents.get(path);
    },
  };
}
