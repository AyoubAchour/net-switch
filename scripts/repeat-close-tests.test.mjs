import assert from 'node:assert/strict';
import test from 'node:test';
import { Results } from './repeat-close-tests.mjs';

test('repeat evidence requires the exact run and pass counts', () => {
  const results = new Results(['TestCap', 'TestCap/full']);
  for (let i = 0; i < 3; i++) for (const Test of results.cases.keys()) {
    results.record({ Test, Action: 'run' });
    results.record({ Test, Action: 'pass' });
  }
  results.verify(3);
  assert.throws(() => results.verify(4), /run count/);
  assert.throws(() => results.verify(2), /run count/);
});

test('an empty or incomplete successful command is not repeat evidence', () => {
  const results = new Results(['TestCap']);
  assert.throws(() => results.verify(1), /run count/);
  results.record({ Test: 'TestCap', Action: 'run' });
  assert.throws(() => results.verify(1), /pass count/);
});

test('a skipped case cannot be hidden by enough other passing repetitions', () => {
  const results = new Results(['TestCap']);
  results.record({ Test: 'TestCap', Action: 'run' });
  results.record({ Test: 'TestCap', Action: 'pass' });
  results.record({ Test: 'TestOtherCap', Action: 'skip' });
  assert.throws(() => results.verify(1), /skipped repeat cases/);
});

test('a failed package or subtest fails the evidence check', () => {
  for (const Test of [undefined, 'TestOtherCap']) {
    const results = new Results([]);
    results.record({ Test, Action: 'fail' });
    assert.throws(() => results.verify(1), /failed or skipped/);
  }
});
