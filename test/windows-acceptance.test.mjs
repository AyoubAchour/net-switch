import assert from 'node:assert/strict';
import test from 'node:test';
import { BaselineDefect, Report } from '../tests/windows/report.mjs';

test('a baseline defect exemption cannot swallow a broken test or target', async () => {
  const report = new Report('baseline');
  await assert.rejects(report.test('unreachable baseline', 'baseline-defect', async () => { throw new Error('target down'); }), /target down/);
  assert.equal(report.results[0].status, 'fail');
});

test('confirmed baseline defects fail when the 1.0 profile is selected', async () => {
  const baseline = new Report('baseline');
  const defect = async () => { throw new BaselineDefect('port stalls', { elapsedMs: 60000 }); };
  await baseline.test('port reuse', 'baseline-defect', defect);
  assert.equal(baseline.results[0].status, 'confirmed-defect');
  const v1 = new Report('v1');
  await assert.rejects(v1.test('port reuse', 'baseline-defect', defect), /port stalls/);
});

test('parity cases cannot opt into baseline exemptions', async () => {
  const report = new Report('baseline');
  await assert.rejects(report.test('pin', 'parity', async () => { throw new BaselineDefect('wrong line'); }), /wrong line/);
  assert.equal(report.results[0].status, 'fail');
});
