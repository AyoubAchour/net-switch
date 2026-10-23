import assert from 'node:assert/strict';
import { test } from 'node:test';
import { passReader, required } from '../../scripts/run-native-proof.mjs';
test('hosted proof requires every actual PASS and rejects skips or empty selections',()=>{
  for(const names of Object.values(required)) {
    const p=passReader(names);
    p.push(`PASS\n--- SKIP: ${names[0]} (0.00s)\n`);
    assert.deepEqual(p.missing(),names);
    for(const name of names) {p.push('    --- PA');p.push(`SS: ${name} (0.01s)\n`);}
    assert.deepEqual(p.missing(),[]);
  }
  const p=passReader(['real']);p.push('x'.repeat(9000)+'--- PASS: real (0s)\n');assert.deepEqual(p.missing(),['real']);
});
