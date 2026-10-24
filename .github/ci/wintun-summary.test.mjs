import assert from 'node:assert/strict';
import {test} from 'node:test';
import {IntegritySummary, ratioSpread, diagnosticBudget} from '../../scripts/wintun-integrity-summary.mjs';

const emit=(s,r)=>s.line(`WINTUN_RESULT ${JSON.stringify(r)}`);
const samples=ratios=>ratios.map((ratio,pair)=>({status:'valid',value:100*ratio,pair,metric:'test'}));
function fixture({scenario='proof', ratio=1, ratios, modeRatios={}, captureRatio=1, captureModeRatios={}, omitPhase=false, omitCompletion=false}={}) {
 const s=new IntegritySummary({scenario});
 s.line(`INTEGRITY_RUN_START scenario=${scenario} boundary=receive repeat=1`);
 const bs=scenario==='proof'?['receive','ingress','echo','output','send','host']:['receive'];
 const modes=scenario==='full'?['ours','dll','inprocess']:['ours','dll'];
 let index=0;
 const connection=(phase,transfer)=>emit(s,{test:'tcp_integrity',verdict:'ok',phase,repeat:'1',connection:{transfer,payload_id:++index,
  host_expected_sha256:'a'.repeat(64),host_actual_sha256:'a'.repeat(64),coverage:{host_receive:{bytes:67108864}}}});
 for(const b of bs)for(const mode of modes){
  const rr=ratios?ratios.splice(0,3):Array(3).fill(modeRatios[mode]??ratio);
  emit(s,{test:'integrity_overhead',boundary:b,mode,clean:samples([1,1,1]),diagnostic:samples(rr)});
  for(let i=0;i<30;i++)connection('calibration',`TestWintunIntegrityProof/${b}/${mode}/${i}`);
 }
 if(scenario==='proof')for(const mode of ['ours','dll'])emit(s,{test:'capture_overhead',mode,clean:samples(Array(8).fill(1)),capture:samples(Array(8).fill(captureModeRatios[mode]??captureRatio))});
 else for(const phase of scenario==='full'?['performance-dll','performance-inprocess']:['performance-dll']) {
  for(const metric of scenario==='full'?['tcp_1_MBps','tcp_8_MBps']:['tcp_8_MBps'])if(!omitPhase)emit(s,{test:'integrity_pairs_complete',phase,repeat:'1',metric,pairs:12});
  const perMode=scenario==='full'?156:120;
  for(let i=0;i<perMode*2;i++){const mode=i<perMode?'ours':phase.endsWith('dll')?'dll':'inprocess';connection(phase,`TestWintunPerformance/${phase}/${mode}/${i}`);}
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
 const partial=fixture({captureModeRatios:{ours:.94}});partial.line('--- FAIL: TestWintunCaptureProof/ours');partial.line('INTEGRITY_PHASE_FAILED phase=capture-proof exit=1');
 assert.equal(partial.result(1).mode_results.dll.clean_exposure_connections,180);
 assert.equal(partial.result(1).mode_results.ours.clean_exposure_connections,0);
});
test('quartiles use linear interpolation and do not mutate paired order',()=>{
 const a=[4,1,3,2];assert.deepEqual(ratioSpread(a),{pairs:4,min:1,p25:1.75,median:2.5,p75:3.25,max:4,below_080:0});assert.deepEqual(a,[4,1,3,2]);
});

for(const scenario of ['proof','isolated','full'])for(const slow of scenario==='full'?['dll','ours','inprocess']:['dll','ours'])test(`${scenario}: slow ${slow} cannot borrow the other mode's speed or erase its exposure`,()=>{
 const r=fixture({scenario,modeRatios:{[slow]:.7}}).result(0);
 assert.equal(r.verdict,'diagnostic_invalid');assert.equal(r.exit,0);
 assert.equal(r.mode_results[slow].clean_exposure_connections,0);
 const good=slow==='dll'?'ours':'dll';
 assert.equal(r.mode_results[good].verdict,'no_corruption_observed');
 assert.ok(r.mode_results[good].clean_exposure_connections>0);
 assert.equal(r.mode_results[slow].overhead.median,.7);
 assert.ok(r.clean_exposure_connections>0);
});
test('payload/integrity evidence in every replay path is fatal, even with complete TCP data',()=>{
 for(const message of ['latency payload mismatch','UDP echo corruption','ping-pong payload corruption','recovery lost packet integrity','injected trip payload mismatch','registrar session packet corruption','shared-section packet corruption','payload integrity failure: DLL receive ring: The data is invalid.']) {
  const s=fixture({scenario:'full',modeRatios:{dll:.7}});s.line(`test.go:1: ${message}`);s.line('--- FAIL: TestWintunPerformance');
  assert.equal(s.result(1).verdict,'integrity_failure',message);assert.equal(s.result(1).exit,1);assert.equal(s.result(1).clean_exposure_connections,0);
 }
 const s=fixture({scenario:'full'});emit(s,{test:'parallel_udp',invalid_delivered:1});assert.equal(s.result(0).verdict,'integrity_failure');
 const nested=fixture({scenario:'full'});emit(nested,{test:'performance_sample',sample:{status:'invalid',metric:'udp_8_MBps',error:'UDP client: exit status 1\n--- FAIL: TestWintunUDPClient\n payload integrity failure: UDP echo corruption'}});assert.equal(nested.result(1).verdict,'integrity_failure');
});
test('natural ring corruption is evidence; injected recovery damage and ordinary errors are not',()=>{
 const natural=fixture({scenario:'full'});natural.line('INTEGRITY_PHASE_START scenario=full phase=performance-dll');natural.line('Wintun ring corruption: Send invalid entry (head=4)');assert.equal(natural.result(0).verdict,'integrity_failure');
 const injected=fixture({scenario:'full'});injected.line('INTEGRITY_PHASE_START scenario=full phase=ring-recovery');injected.line('=== RUN   TestWintunRecoveryAndCancellation');injected.line('Wintun ring corruption recovered: Send packet failed validation');assert.equal(injected.result(0).verdict,'no_corruption_observed');
 const error=fixture({scenario:'full'});emit(error,{test:'parallel_udp',invalid_delivered:0,read_errors:1});error.line('--- FAIL: TestWintunParallelUDP: UDP read error or insufficient delivered packets');assert.equal(error.result(1).verdict,'test_failed');
});
test('runner deadline includes setup and leaves summary headroom',()=>{
 assert.equal(diagnosticBudget('1000',900),100);
 assert.equal(diagnosticBudget('1000',1001),0);
 assert.equal(diagnosticBudget(undefined,0),0);
 assert.equal(diagnosticBudget('bad',0),0);
 assert.equal(diagnosticBudget(String(75*60*1000),0),48*60*1000);
});

const ringWarning='2026/10/24 02:44:55 WARN Wintun ring corruption recovered adapter=NsRingCI error="Wintun ring corruption: Send packet failed validation (head=3509468 tail=3510700 size=1228 capacity=8388608)" corruptions=1';
function ringIncident(s,{mode='ours',testPath='TestWintunPerformance/pair2/udp_8_MBps/ours',repeat='1',instances=2}={}) {
 s.line(`INTEGRITY_PHASE_START scenario=full repeat=${repeat} phase=performance-inprocess diagnostic=1`);
 s.line(`=== RUN   ${testPath}`);
 s.line(ringWarning);
 for(const event of instances===2?['pumps_joined','closed']:['pumps_joined'])emit(s,{mode,phase:'performance-inprocess',repeat,scenario:'full',event,stats:{Corruptions:1,Recoveries:1},test:'integrity_session',test_path:testPath});
}
test('a ring rejection in one UDP mode is named and attributed without blaming the other modes',()=>{
 const s=fixture({scenario:'full'});ringIncident(s);
 const r=s.result(0);
 assert.equal(r.verdict,'integrity_failure');assert.equal(r.exit,1);
 assert.deepEqual(r.integrity_evidence_kinds,['ring_rejection']);
 assert.equal(r.payload_mismatch_incidents,0);assert.equal(r.ring_rejection_incidents,1);
 assert.deepEqual(r.mode_results.ours.failure_kinds,['ring_rejection']);
 assert.equal(r.mode_results.ours.verdict,'integrity_failure');
 assert.deepEqual(r.mode_results.dll.failure_kinds,[]);
 assert.deepEqual(r.mode_results.inprocess.failure_kinds,[]);
 assert.equal(r.mode_results.dll.verdict,'no_corruption_observed');
 assert.equal(r.clean_exposure_connections,0);assert.ok(r.observed_exposure_connections>0);
});
test('a delivered payload mismatch is named separately and stays fatal',()=>{
 const s=fixture({scenario:'full'});
 emit(s,{test:'tcp_payload_difference',verdict:'integrity_failure',mode:'dll',phase:'performance-dll',repeat:'1',test_path:'TestWintunPerformance/pair0/tcp_8_MBps/dll'});
 const r=s.result(0);
 assert.equal(r.verdict,'integrity_failure');assert.equal(r.exit,1);
 assert.deepEqual(r.integrity_evidence_kinds,['payload_mismatch']);
 assert.equal(r.payload_mismatch_incidents,1);assert.equal(r.ring_rejection_incidents,0);
 assert.deepEqual(r.mode_results.dll.failure_kinds,['payload_mismatch']);
 assert.equal(r.clean_exposure_connections,0);
});
test('a warning and repeated counter snapshots for one incident count once',()=>{
 const s=fixture({scenario:'full'});ringIncident(s);
 const r=s.result(0);
 assert.equal(r.ring_rejection_incidents,1);
 assert.equal(r.integrity_evidence_records,1);
});
test('a clean run names no evidence kind and keeps its clean exposure',()=>{
 const r=fixture({scenario:'full'}).result(0);
 assert.equal(r.verdict,'no_corruption_observed');assert.equal(r.exit,0);
 assert.deepEqual(r.integrity_evidence_kinds,[]);
 assert.equal(r.payload_mismatch_incidents,0);assert.equal(r.ring_rejection_incidents,0);
 assert.ok(r.clean_exposure_connections>0);
});
