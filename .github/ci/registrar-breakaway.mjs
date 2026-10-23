import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';

// Source guard for the one exception recorded in spec §3.4. Test code and
// dependencies cannot authorize a new product launch path.
const hits = execFileSync('git', ['grep', '--no-color', '-n', '-F', 'CREATE_BREAKAWAY_FROM_JOB', '--', 'internal', 'cmd'], { encoding: 'utf8' })
  .trim().split('\n').filter(line => !line.split(':')[0].endsWith('_test.go'));
assert.equal(hits.length, 1, `Unexpected breakaway launch sites: ${hits.join('\n')}`);
assert.match(hits[0], /^internal\/wintun\/registrar_windows\.go:\d+:\s*flags \|= windows\.CREATE_BREAKAWAY_FROM_JOB\s*$/);
console.log('Only the atomic registrar launch requests breakaway.');
