import assert from 'node:assert/strict';
import {test} from 'node:test';
import {IntegritySummary, ratioSpread} from '../../scripts/wintun-integrity-summary.mjs';

const emit=(s,r)=>s.line(`WINTUN_RESULT ${JSON.stringify(r)}`);
const samples=ratios=>ratios.map((ratio,pair)=>({status:'valid',value:100*ratio,pair,metric:'test'}));
function fixture({scenario='proof', ratio=1, ratios, captureRatio=1, omitPhase=false, omitCompletion=false}={}) {
 const s=new IntegritySummary({scenario});
 s.line(`INTEGRITY_RUN_START scenario=${scenario} boundary=receive repeat=1`);
 const bs=scenario==='proof'?['receive','ingress','echo','output','send','host']:['receive'];
 const modes=scenario==='full'?['ours','dll','inprocess']:['ours','dll'];
 let index=0;
 const connection=(phase,transfer)=>emit(s,{test:'tcp_integrity',verdict:'ok',phase,repeat:'1',connection:{transfer,payload_id:++index,
  host_expected_sha256:'a'.repeat(64),host_actual_sha256:'a'.repeat(64),coverage:{host_receive:{bytes:67108864}}}});
 for(const b of bs)for(const mode of modes){
  const rr=ratios?ratios.splice(0,3):[ratio,ratio,ratio];
  emit(s,{test:'integrity_overhead',boundary:b,mode,clean:samples([1,1,1]),diagnostic:samples(rr)});
  for(let i=0;i<30;i++)connection('calibration',`TestWintunIntegrityProof/${b}/${mode}/${i}`);
 }
 if(scenario==='proof')for(const mode of ['ours','dll'])emit(s,{test:'capture_overhead',mode,clean:samples(Array(8).fill(1)),capture:samples(Array(8).fill(captureRatio))});
 else for(const phase of scenario==='full'?['performance-dll','performance-inprocess']:['performance-dll']) {
  for(const metric of scenario==='full'?['tcp_1_MBps','tcp_8_MBps']:['tcp_8_MBps'])if(!omitPhase)emit(s,{test:'integrity_pairs_complete',phase,repeat:'1',metric,pairs:12});
  for(let i=0;i<(scenario==='full'?312:240);i++)connection(phase,`TestWintunPerformance/${phase}/${i}`);
 }
 const count=bs.length*modes.length;
 if(!omitCompletion){emit(s,{test:'integrity_proof_complete',completed_configurations:count,expected_configurations:count,expected_pairs:count*3});s.line('INTEGRITY_JOB_COMPLETE');}
 return s;
}

test('one slow boundary no longer gates the job; all ratios and the spread remain',()=>{
 const s=fixture({ratios:[.7,.7,.7,...Array(33).fill(.9)]});
 const r=s.result(0);
 assert.equal(r.verdict,'no_corruption_observed');
 assert.equal(r.clean_exposure_connections,360);
 assert.deepEqual(r.overhead,{pairs:36,min:.7,p25:.9,median:.9,p75:.9,max:.9,below_080:3});
});
for(const scenario of ['proof','isolated','full'])test(`${scenario}: >20% overhead is invalid, nonfatal and never clean exposure`,()=>{
 const s=fixture({scenario,ratio:.79});
 const r=s.result(0);
 assert.equal(r.verdict,'diagnostic_invalid');assert.equal(r.exit,0);
 assert.equal(r.clean_exposure_connections,0);assert.ok(r.observed_exposure_connections>0);
 emit(s,{test:'tcp_payload_difference',verdict:'integrity_failure'});
 assert.equal(s.result(0).exit,1);assert.equal(s.result(0).verdict,'integrity_failure');
});
test('exact 20% bound stays valid and an incomplete calibration cannot be averaged away',()=>{
 assert.equal(fixture({ratio:.8}).result(0).verdict,'no_corruption_observed');
 const s=fixture({ratio:.79,omitCompletion:true});
 assert.equal(s.result(0).verdict,'diagnostic_incomplete');assert.equal(s.result(0).exit,1);
 assert.equal(s.result(0).overhead,null,'no aggregate from an incomplete job');
});
test('unrelated failures are summarized without failing or crediting the job',()=>{
 const s=fixture({scenario:'full'});s.line('--- FAIL: TestWintunRecoveryAndCancellation (2s)');
 assert.equal(s.result(1).verdict,'test_failed');assert.equal(s.result(1).exit,0);assert.equal(s.result(1).clean_exposure_connections,0);
 const missing=fixture({scenario:'full',omitPhase:true});missing.line('--- FAIL: TestWintunPerformance');
 assert.equal(missing.result(1).verdict,'diagnostic_incomplete');assert.equal(missing.result(1).exit,1);
});
test('invalid or duplicate pairs, failed TCP samples, missing records and timeouts fail closed',()=>{
 for(const mutate of [
  s=>emit(s,{test:'integrity_overhead',boundary:'receive',mode:'ours',clean:samples([1,1,1]),diagnostic:samples([1,1,1])}),
  s=>emit(s,{test:'performance_sample',diagnostic:true,sample:{metric:'tcp_8_MBps',status:'invalid'}}),
  s=>s.line('WINTUN_RESULT {'),
  s=>s.line('INTEGRITY_PHASE_TIMEOUT phase=calibration'),
  s=>{s.calibrationConnections--;},
 ]){const s=fixture();mutate(s);assert.equal(s.result(0).verdict,'diagnostic_incomplete');assert.equal(s.result(0).exit,1);}
 const s=new IntegritySummary();assert.equal(s.result(0).verdict,'diagnostic_incomplete');
 s.line('TCP payload hash mismatch: local=198.19.240.1:12345 stream=0');
 assert.equal(s.result(1).verdict,'integrity_failure');
});
test('ordinary capture guard remains visible, nonfatal and excluded when only its timing fails',()=>{
 const s=fixture({captureRatio:.94});s.line('--- FAIL: TestWintunCaptureProof');
 assert.equal(s.result(1).verdict,'diagnostic_invalid');assert.equal(s.result(1).exit,0);assert.equal(s.result(1).clean_exposure_connections,0);
});
test('quartiles use linear interpolation and do not mutate paired order',()=>{
 const a=[4,1,3,2];assert.deepEqual(ratioSpread(a),{pairs:4,min:1,p25:1.75,median:2.5,p75:3.25,max:4,below_080:0});assert.deepEqual(a,[4,1,3,2]);
});
