import { spawn } from 'node:child_process';
import { writeFileSync } from 'node:fs';
import { createInterface } from 'node:readline';
import { pathToFileURL } from 'node:url';

const boundaries = ['receive','ingress','echo','output','send','host'];
// Stable shared marker plus old messages, including child-process errors nested
// inside a JSON sample error. Do not treat "integrity-invalid comparison" alone
// or deliberate ring fault injections as observed payload corruption.
const payloadFailure = /payload integrity failure|\b(?:payload|packet|integrity)(?: hash)? mismatch\b|\b(?:payload|packet) corruption\b|UDP echo corruption|recovery lost packet integrity|damaged packet escaped|bad packet bounds|packet path failed:.*Wintun ring corruption/i;
const naturalPhases = new Set(['proof','capture-proof','calibration','performance-dll','performance-inprocess','ping-pong','profile-dll','profile-ours']);
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
  phase=null; currentTest=null; byMode=new Map();
  line(line) {
    if (payloadFailure.test(line)) this.corruption++;
    const phase=/INTEGRITY_PHASE_START .*?phase=([\w-]+)/.exec(line);
    if (phase) this.phase=phase[1];
    if (/INTEGRITY_CALIBRATION_START/.test(line)) this.phase='calibration';
    const running=/=== RUN\s+(\S+)/.exec(line);
    if (running) this.currentTest=running[1].split('/')[0];
    // Recovery/lifetime tests intentionally damage rings. Only natural traffic
    // paths use the raw ring error as evidence; actual payload failures above
    // remain fatal in EVERY test, including tests which inject delays/faults.
    if ((naturalPhases.has(this.phase) || this.currentTest==='TestWintunParallelUDP') && /Wintun ring corruption(?: recovered|:)|packet failed validation|invalid entry/.test(line)) this.corruption++;
    if (/INTEGRITY_JOB_COMPLETE/.test(line)) this.complete=true;
    if (/INTEGRITY_PHASE_TIMEOUT/.test(line)) { this.timeouts++; this.notes.add(line.trim()); }
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
    if (r.test==='parallel_udp' && r.invalid_delivered>0) this.corruption++;
    if ((naturalPhases.has(this.phase) && r.test==='integrity_session' || r.test==='parallel_udp') && r.stats?.Corruptions>0) this.corruption++;
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
        const mode=/\/(ours|dll|inprocess)\//.exec(c.transfer)?.[1];
        if (!mode) throw Error('missing connection mode');
        const counts=this.byMode.get(mode)??{connections:0,calibration:0};
        counts.connections++;
        if (/TestWintunIntegrityProof\//.test(c.transfer)) { this.calibrationConnections++; counts.calibration++; }
        this.byMode.set(mode,counts);
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
    const expectedByMode=Object.fromEntries(modes.map(m=>[m,0]));
    if (this.scenario==='proof') for (const mode of modes) expectedByMode[mode]=chosen.length*30;
    else for (const key of this.expectedPhases.keys()) {
      const amount=this.scenario==='isolated'?120:156;
      expectedByMode.ours+=amount;
      expectedByMode[key.endsWith('performance-dll')?'dll':'inprocess']+=amount;
    }
    for (const mode of modes) {
      const counts=this.byMode.get(mode);
      missing ||= counts?.calibration!==chosen.length*30;
      missing ||= (this.scenario==='proof'?counts?.calibration:counts?.connections-counts?.calibration)!==expectedByMode[mode];
    }
    missing ||= this.byMode.size!==modes.length;
    // A nonzero exit without a recognized test failure is an unfinished runner.
    missing ||= code!==0 && this.failures.length===0;
    const spread=missing || this.incomplete || this.timeouts ? null : ratioSpread(ratios);
    const captureInvalid=[...this.capture.values()].some(s=>s.median<.95);
    const captureTimingOnly=captureInvalid && this.failures.length>0 && this.failures.every(l=>/TestWintunCaptureProof|phase=capture-proof\b/.test(l));
    const otherFailure=(code!==0 || this.failures.length>0) && !captureTimingOnly;
    const modeResults=Object.fromEntries(modes.map(mode=>{
      const counts=this.byMode.get(mode)??{connections:0,calibration:0};
      const overhead=spread ? ratioSpread(chosen.flatMap(b=>this.configurations.get(`${b}/${mode}`))) : null;
      const observed=this.scenario==='proof'?counts.calibration:counts.connections-counts.calibration;
      const verdict=this.corruption?'integrity_failure':!overhead?'diagnostic_incomplete':overhead.median<.80 || (this.capture.get(mode)?.median??1)<.95?'diagnostic_invalid':otherFailure?'test_failed':'no_corruption_observed';
      return [mode,{verdict,overhead,observed_exposure_connections:observed,calibration_connections:counts.calibration,clean_exposure_connections:verdict==='no_corruption_observed'?observed:0}];
    }));
    const invalidModes=modes.filter(m=>modeResults[m].verdict==='diagnostic_invalid');
    const verdict=this.corruption ? 'integrity_failure' : this.incomplete || this.timeouts || missing ? 'diagnostic_incomplete' : invalidModes.length ? 'diagnostic_invalid' : otherFailure ? 'test_failed' : 'no_corruption_observed';
    return {verdict, exit:['integrity_failure','diagnostic_incomplete'].includes(verdict)?1:0, original_exit:code,
      overhead:spread, qualification_scope:'per_mode', mode_results:modeResults, invalid_modes:invalidModes, minimum_ratio:.80, capture_overhead:Object.fromEntries(this.capture), capture_invalid:captureInvalid,
      diagnostic_connections:this.connections, calibration_connections:this.calibrationConnections, observed_exposure_connections:observedExposure,
      clean_exposure_connections:Object.values(modeResults).reduce((n,r)=>n+r.clean_exposure_connections,0),
      integrity_evidence_records:this.corruption, incomplete_records:this.incomplete, timeout_records:this.timeouts, incomplete_structure:Boolean(missing),
      notes:[...this.notes], failed_tests_and_phases:this.failures};
  }
}

export function diagnosticBudget(deadline, now=Date.now()) {
  const limit=Number(deadline);
  return Number.isFinite(limit) && limit>0 ? Math.max(0,Math.min(48*60*1000,limit-now)) : 0;
}

if (process.argv[1] && import.meta.url===pathToFileURL(process.argv[1]).href) {
  if (process.env.GITHUB_ACTIONS!=='true' || process.env.RUNNER_ENVIRONMENT!=='github-hosted') throw Error('Hosted CI only');
  const summary=new IntegritySummary({scenario:process.env.INTEGRITY_SCENARIO});
  const writeSummary=body=>{if(process.env.GITHUB_STEP_SUMMARY)writeFileSync(process.env.GITHUB_STEP_SUMMARY,body);};
  // A hard runner stop leaves an explicit incomplete placeholder, not clean
  // credit. The final verdict replaces it only after all output is consumed.
  writeSummary('### Integrity: diagnostic_incomplete\n\nExecution has not finished. Eligible clean transfers: **0**. A missing final INTEGRITY_SUMMARY is incomplete, including a job timeout.\n');
  console.log('INTEGRITY_PENDING_SUMMARY verdict=diagnostic_incomplete clean_exposure_connections=0');
  let child, timer, fallback, finished=false, expiring=false;
  const finish=code=>{
    if(finished)return;
    finished=true; clearTimeout(timer); clearTimeout(fallback);
    const result=summary.result(code??1);
    console.log(`INTEGRITY_SUMMARY ${JSON.stringify(result)}`);
    writeSummary(
      `### Payload integrity: ${result.verdict}\n\nEligible clean transfers: **${result.clean_exposure_connections}**; observed: ${result.observed_exposure_connections}; calibration connections: ${result.calibration_connections}.\n\n`+
      `Per-mode results (each median must be >=0.80): ${JSON.stringify(result.mode_results)}\n\n`+
      [...result.notes,...result.failed_tests_and_phases].map(line=>`- ${line.replaceAll('<','&lt;')}\n`).join('')+
      '\nCorruption in any protocol or incomplete diagnostics fail this investigation. An overhead-invalid mode receives zero clean credit; valid modes still count. Full evidence remains in the log; no sample was retried or replaced. The release blocker remains open.\n');
    process.exitCode=result.exit;
  };
  const expire=()=>{
    if(finished || expiring)return;
    expiring=true;
    summary.line('INTEGRITY_PHASE_TIMEOUT phase=runner verdict=diagnostic_incomplete');
    if(child?.pid && child.exitCode===null && child.signalCode===null) {
      const killer=spawn('taskkill',['/PID',String(child.pid),'/T','/F'],{stdio:'ignore',windowsHide:true});
      killer.on('error',()=>{});
    }
    // Never let a child retaining its pipe prevent the final incomplete verdict.
    fallback=setTimeout(()=>{finish(124);process.exit(1);},5000);
  };
  const budget=diagnosticBudget(process.env.INTEGRITY_JOB_DEADLINE_MS);
  if(!budget) {summary.line('INTEGRITY_PHASE_TIMEOUT phase=setup');finish(124);}
  else {
    child=spawn('pwsh',['-NoProfile','-File','scripts/test-wintun-integrity.ps1','-Repeats',process.env.INTEGRITY_REPEATS,'-Scenario',process.env.INTEGRITY_SCENARIO,'-Arch',process.env.RUNNER_ARCH],{stdio:['ignore','pipe','pipe'],windowsHide:true});
    timer=setTimeout(expire,budget);
    for (const stream of [child.stdout,child.stderr]) createInterface({input:stream}).on('line',line=>{ process.stdout.write(`${line}\n`); summary.line(line); });
    child.on('error',error=>{ console.error(error.message); finish(1); });
    child.on('close',finish);
    process.once('SIGTERM',expire);process.once('SIGINT',expire);
  }
}
