import assert from 'node:assert/strict';
import {test} from 'node:test';
import {IntegritySummary} from '../../scripts/wintun-integrity-summary.mjs';

test('overhead failure survives later successful host records and identifies the failed gate',()=>{
 const s=new IntegritySummary();
 s.line('WINTUN_RESULT {"test":"integrity_overhead","verdict":"diagnostic_overhead_exceeded","boundary":"ingress","mode":"dll","median_diagnostic_over_clean":0.797922243414923,"minimum_ratio":0.8}');
 s.line('WINTUN_RESULT {"test":"tcp_integrity","verdict":"ok","boundary":"host"}');
 s.line('--- FAIL: TestWintunIntegrityProof (244s)');
 assert.equal(s.result(1).verdict,'diagnostic_overhead_exceeded');
 assert.deepEqual(s.result(1).failed_overhead_gates,[{boundary:'ingress',mode:'dll',ratio:0.797922243414923,minimum_ratio:0.8}]);
 assert.equal(s.result(0).exit,1);
 s.line('WINTUN_RESULT {"test":"tcp_payload_difference","verdict":"integrity_failure"}');
 assert.equal(s.result(1).verdict,'integrity_failure','real corruption wins over the overhead failure');
});

test('test failures, incomplete diagnostics and positive corruption stay distinct',()=>{
 const s=new IntegritySummary();
 s.line('INTEGRITY_RUN_COMPLETE repeat=1');
 s.line('body did not recover: stats');
 s.line('--- FAIL: TestWintunRecoveryAndCancellation (2s)');
 s.line('integrity-invalid comparison: pair=9 mode=dll metric=udp_8_MBps: The data is invalid.');
 assert.equal(s.result(1).verdict,'test_failed');
 assert.equal(s.result(1).exit,1);
 s.line('WINTUN_RESULT {"test":"tcp_integrity","verdict":"diagnostic_incomplete"}');
 assert.equal(s.result(1).verdict,'diagnostic_incomplete');
 s.line('WINTUN_RESULT {"test":"tcp_integrity_first_failure"}');
 assert.equal(s.result(1).verdict,'integrity_failure');
 assert.equal(s.result(0).exit,1,'never green corruption even with a lost child error');
 const hash=new IntegritySummary();
 hash.line('TCP payload hash mismatch: local=198.19.240.1:12345 stream=0');
 assert.equal(hash.result(1).verdict,'integrity_failure','plain SHA failure is evidence even without an excerpt');
});
test('empty/truncated output is incomplete, complete clean output is observational only',()=>{
 const s=new IntegritySummary();
 assert.equal(s.result(0).verdict,'diagnostic_incomplete');
 s.line('INTEGRITY_RUN_COMPLETE repeat=2');
 s.line('WINTUN_RESULT {"test":"tcp_integrity","verdict":"ok"}');
 assert.equal(s.result(0).verdict,'no_corruption_observed');
 assert.equal(s.result(0).diagnostic_connections,1);
 s.line('WINTUN_RESULT {');
 assert.equal(s.result(0).verdict,'diagnostic_incomplete');
});
