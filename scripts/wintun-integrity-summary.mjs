import { spawn } from 'node:child_process';
import { appendFileSync } from 'node:fs';
import { createInterface } from 'node:readline';
import { pathToFileURL } from 'node:url';

const boundaries = ['receive','ingress','echo','output','send','host'];
export function ratioSpread(values) {
  if (!values.length) return null;
  const sorted = [...values].sort((a,b) => a-b);
  const q = f => { const x=(sorted.length-1)*f, i=Math.floor(x); return sorted[i]+(sorted[Math.ceil(x)]-sorted[i])*(x-i); };
  return {pairs:sorted.length, min:sorted[0], p25:q(.25), median:q(.5), p75:q(.75), max:sorted.at(-1), below_080:sorted.filter(x=>x<.8).length};
}

function paired(clean, observed, count) {
  if (!Array.isArray(clean) || !Array.isArray(observed) || clean.length !== count || observed.length !== count) throw Error('missing pairs');
  return clean.map((a,i) => {
    const b=observed[i];
    for (const s of [a,b]) if (s?.status !== 'valid' || s.pair !== i || s.error || !Number.isFinite(s.value) || s.value <= 0) throw Error('invalid sample');
    if (a.metric !== b.metric) throw Error('different metrics');
    const ratio=b.value/a.value;
    if (!Number.isFinite(ratio) || ratio<=0) throw Error('invalid ratio');
    return ratio;
  });
}

// Raw observations never equal eligible clean exposure. Only the final, complete
// job-wide verdict can credit connections; overhead-invalid jobs remain visible.
export class IntegritySummary {
  constructor({scenario='proof'}={}) { this.scenario=scenario; }
  corruption=0; incomplete=0; timeouts=0; connections=0; calibrationConnections=0; complete=false;
  failures=[]; notes=new Set(); configurations=new Map(); capture=new Map(); proof=null;
  expectedPhases=new Map(); boundary=null; connectionIDs=new Set();
  line(line) {
    if (/TCP payload hash mismatch/.test(line)) this.corruption++;
    if (/INTEGRITY_JOB_COMPLETE/.test(line)) this.complete=true;
    if (/INTEGRITY_PHASE_TIMEOUT/.test(line)) this.timeouts++;
    if (/INTEGRITY_RUN_FAILED.*diagnostic_incomplete/.test(line)) this.incomplete++;
    if (/--- FAIL:|INTEGRITY_PHASE_FAILED/.test(line) && this.failures.length<40) this.failures.push(line.trim());
    if (/body did not recover:|alignment did not recover:|throughput regression tcp_8_MBps:/.test(line)) this.notes.add(line.trim());
    const start=/INTEGRITY_RUN_START scenario=(\w+) boundary=(\w+) repeat=(\d+)/.exec(line);
    if (start) {
      if (start[1] !== this.scenario || (this.boundary && this.boundary !== start[2])) this.incomplete++;
      this.boundary=start[2];
      if (this.scenario !== 'proof') for (const phase of this.scenario==='full' ? ['performance-dll','performance-inprocess'] : ['performance-dll']) {
        const key=`${start[3]}/${phase}`;
        if (this.expectedPhases.has(key)) this.incomplete++;
        this.expectedPhases.set(key,new Set());
      }
    }
    const pos=line.indexOf('WINTUN_RESULT ');
    if (pos<0) return;
    let r;
    try { r=JSON.parse(line.slice(pos+14)); } catch { this.incomplete++; return; }
    if (r.verdict==='integrity_failure' || r.test==='tcp_integrity_first_failure' || r.test==='tcp_payload_difference') this.corruption++;
    if (r.verdict==='diagnostic_incomplete') this.incomplete++;
    try {
      if (r.test==='integrity_overhead') {
        const key=`${r.boundary}/${r.mode}`;
        if (this.configurations.has(key)) throw Error('duplicate configuration');
        this.configurations.set(key,paired(r.clean,r.diagnostic,3));
      }
      if (r.test==='integrity_proof_complete') {
        if (this.proof) throw Error('duplicate calibration');
        this.proof=r;
      }
      if (r.test==='capture_overhead') {
        if (this.capture.has(r.mode)) throw Error('duplicate capture proof');
        this.capture.set(r.mode,ratioSpread(paired(r.clean,r.capture,8)));
      }
      if (r.test==='integrity_proof_sample' && r.sample?.status!=='valid') throw Error('incomplete proof transfer');
      if (r.test==='performance_sample' && r.diagnostic && r.sample?.metric?.startsWith('tcp_') && r.sample.status!=='valid') throw Error('incomplete exposure transfer');
      if (r.test==='integrity_pairs_complete' && r.metric?.startsWith('tcp_')) {
        const set=this.expectedPhases.get(`${r.repeat}/${r.phase}`);
        if (!set || set.has(r.metric) || r.pairs!==12) throw Error('invalid exposure pairs');
        set.add(r.metric);
      }
      if (r.test==='tcp_integrity') {
        this.connections++;
        const c=r.connection;
        if (!c || !/^[a-f0-9]{64}$/.test(c.host_expected_sha256) || !/^[a-f0-9]{64}$/.test(c.host_actual_sha256)) throw Error('missing host hash');
        if (c.host_expected_sha256!==c.host_actual_sha256) this.corruption++;
        if (c.coverage?.host_receive?.bytes!==67108864 || r.verdict!=='ok') throw Error('incomplete host coverage');
        const key=`${r.phase}/${r.repeat}/${c.transfer}/${c.payload_id}`;
        if (this.connectionIDs.has(key)) throw Error('duplicate connection record');
        this.connectionIDs.add(key);
        if (/TestWintunIntegrityProof\//.test(c.transfer)) this.calibrationConnections++;
      }
    } catch (error) { this.incomplete++; this.notes.add(error.message); }
  }
  result(code) {
    const chosen=this.scenario==='proof' ? boundaries : [this.boundary];
    const modes=this.scenario==='full' ? ['ours','dll','inprocess'] : ['ours','dll'];
    const keys=chosen.flatMap(b=>modes.map(m=>`${b}/${m}`));
    const ratios=[...this.configurations.values()].flat();
    let missing=!this.complete || !this.boundary || !this.proof || keys.some(k=>!this.configurations.has(k)) || this.configurations.size!==keys.length;
    missing ||= this.proof?.completed_configurations!==keys.length || this.proof?.expected_configurations!==keys.length || this.proof?.expected_pairs!==keys.length*3;
    missing ||= this.calibrationConnections!==keys.length*30;
    if (this.scenario==='proof') missing ||= this.capture.size!==2 || !this.capture.has('ours') || !this.capture.has('dll');
    const metrics=this.scenario==='isolated' ? ['tcp_8_MBps'] : ['tcp_1_MBps','tcp_8_MBps'];
    for (const set of this.expectedPhases.values()) missing ||= metrics.some(m=>!set.has(m)) || set.size!==metrics.length;
    const observedExposure=this.scenario==='proof' ? this.calibrationConnections : this.connections-this.calibrationConnections;
    if (this.scenario!=='proof') missing ||= !this.expectedPhases.size || observedExposure!==this.expectedPhases.size*(this.scenario==='isolated'?240:312);
    // A nonzero exit without a recognized test failure is an unfinished runner.
    missing ||= code!==0 && this.failures.length===0;
    const spread=missing || this.incomplete || this.timeouts ? null : ratioSpread(ratios);
    const captureInvalid=[...this.capture.values()].some(s=>s.median<.95);
    const verdict=this.corruption ? 'integrity_failure' : this.incomplete || this.timeouts || missing ? 'diagnostic_incomplete' : spread.median<.80 || captureInvalid ? 'diagnostic_invalid' : code!==0 || this.failures.length ? 'test_failed' : 'no_corruption_observed';
    return {verdict, exit:['integrity_failure','diagnostic_incomplete'].includes(verdict)?1:0, original_exit:code,
      overhead:spread, minimum_ratio:.80, capture_overhead:Object.fromEntries(this.capture), capture_invalid:captureInvalid,
      diagnostic_connections:this.connections, calibration_connections:this.calibrationConnections, observed_exposure_connections:observedExposure,
      clean_exposure_connections:verdict==='no_corruption_observed'?observedExposure:0,
      integrity_evidence_records:this.corruption, incomplete_records:this.incomplete, incomplete_structure:Boolean(missing),
      notes:[...this.notes], failed_tests_and_phases:this.failures};
  }
}

if (process.argv[1] && import.meta.url===pathToFileURL(process.argv[1]).href) {
  if (process.env.GITHUB_ACTIONS!=='true' || process.env.RUNNER_ENVIRONMENT!=='github-hosted') throw Error('Hosted CI only');
  const child=spawn('pwsh',['-NoProfile','-File','scripts/test-wintun-integrity.ps1','-Repeats',process.env.INTEGRITY_REPEATS,'-Scenario',process.env.INTEGRITY_SCENARIO,'-Arch',process.env.RUNNER_ARCH],{stdio:['ignore','pipe','pipe'],windowsHide:true});
  const summary=new IntegritySummary({scenario:process.env.INTEGRITY_SCENARIO});
  for (const stream of [child.stdout,child.stderr]) createInterface({input:stream}).on('line',line=>{ process.stdout.write(`${line}\n`); summary.line(line); });
  child.on('error',error=>{ console.error(error.message); process.exitCode=1; });
  child.on('close',code=>{
    const result=summary.result(code??1);
    console.log(`INTEGRITY_SUMMARY ${JSON.stringify(result)}`);
    if (process.env.GITHUB_STEP_SUMMARY) appendFileSync(process.env.GITHUB_STEP_SUMMARY,
      `### TCP integrity: ${result.verdict}\n\nEligible clean transfers: **${result.clean_exposure_connections}**; observed: ${result.observed_exposure_connections}; calibration connections: ${result.calibration_connections}.\n\n`+
      `Job-wide paired ratios (minimum allowed median 0.80): ${JSON.stringify(result.overhead)}\n\n`+
      [...result.notes,...result.failed_tests_and_phases].map(line=>`- ${line.replaceAll('<','&lt;')}\n`).join('')+
      '\nOnly integrity evidence or incomplete diagnostics fail this investigation. Invalid and other-test-failed jobs receive zero clean exposure credit. Full evidence remains in the log; no sample was retried or replaced. The release blocker remains open.\n');
    process.exitCode=result.exit;
  });
}
