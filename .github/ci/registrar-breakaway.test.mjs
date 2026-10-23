import assert from 'node:assert/strict';
import { test } from 'node:test';
import { breakawayProblems } from './registrar-breakaway.mjs';
const allowed='internal/wintun/registrar_windows.go:1: flags |= windows.CREATE_BREAKAWAY_FROM_JOB';
test('breakaway guard covers new Go roots and numeric spellings',()=>{
  assert.deepEqual(breakawayProblems([allowed]),[]);
  for(const expression of ['windows.CREATE_BREAKAWAY_FROM_JOB','0x01000000','0x100_0000','16777216','16_777_216','1 << 24','0b1000000000000000000000000','0100000000']) {
    assert.notDeepEqual(breakawayProblems([allowed,`helper/new-package/launch.go:3: flags |= ${expression}`]),[]);
  }
  assert.deepEqual(breakawayProblems([allowed,'vendor/flags.go:1: const mask = 0x01000000','helper/flags_test.go:1: const mask = 16777216']),[]);
});
