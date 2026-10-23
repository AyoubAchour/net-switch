import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { pathToFileURL } from 'node:url';

// Whole tracked Go tree, including future packages, excluding only tests and
// generated dependencies. Literal masks must not bypass the named-flag guard.
export const candidate = 'CREATE_BREAKAWAY_FROM_JOB|0[xX][0-9a-fA-F_]+|1_?6_?7_?7_?7_?2_?1_?6|0[bBoO][0-9_]+|01[0_]+|1[[:space:]]*<<[[:space:]]*24';
export function breakawayProblems(lines) {
  const named = [], problems = [];
  for (const line of lines) {
    const match = /^([^:]+):\d+:(.*)$/.exec(line);
    if (!match) continue;
    const [, path, raw] = match;
    if (path.endsWith('_test.go') || /^(vendor|third_party)\//.test(path)) continue;
    const code = raw.replace(/\/\/.*$/, '');
    if (code.includes('CREATE_BREAKAWAY_FROM_JOB')) {
      named.push(line);
      if (path !== 'internal/wintun/registrar_windows.go' || !/^\s*flags \|= windows\.CREATE_BREAKAWAY_FROM_JOB\s*$/.test(code)) problems.push(line);
    }
    for (const value of code.match(/\b(?:0[xX][0-9a-fA-F_]+|0[bBoO][0-9_]+|[0-9][0-9_]*)\b/g) ?? []) {
      let token = value.replaceAll('_', '');
      if (/^0[0-7]+$/.test(token)) token = `0o${token.slice(1)}`;
      if (BigInt(token) === 16777216n) problems.push(line);
    }
    if (/\b1\s*<<\s*24\b/.test(code)) problems.push(line);
  }
  if (named.length !== 1) problems.push(`expected one registrar breakaway site, got ${named.length}`);
  return problems;
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const output = execFileSync('git', ['grep', '--no-color', '-n', '-E', candidate, '--', '*.go', ':!vendor/**', ':!third_party/**', ':!*_test.go'], {encoding:'utf8', maxBuffer:8<<20});
  assert.deepEqual(breakawayProblems(output.trim().split('\n')), [], 'unexpected breakaway use');
  console.log('Only the atomic registrar launch requests breakaway; whole Go tree and numeric masks checked.');
}
