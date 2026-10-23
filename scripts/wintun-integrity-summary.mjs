import { spawn } from 'node:child_process';
import { appendFileSync } from 'node:fs';
import { createInterface } from 'node:readline';
import { pathToFileURL } from 'node:url';

// Summarize evidence, never infer corruption from a red test or the comparator's
// "integrity-invalid" label. Preserve the child's failure status in every case.
export class IntegritySummary {
  corruption = 0; incomplete = 0; timeouts = 0; connections = 0; complete = false;
  failures = []; notes = new Set(); overheadFailures = [];
  line(line) {
    // SHA also catches a changed sender oracle in ordinary/profile transfers.
    if (/TCP payload hash mismatch/.test(line)) this.corruption++;
    if (/INTEGRITY_RUN_COMPLETE|INTEGRITY_PROOF_COMPLETE/.test(line)) this.complete = true;
    if (/INTEGRITY_PHASE_TIMEOUT/.test(line)) this.timeouts++;
    if (/INTEGRITY_RUN_FAILED.*diagnostic_incomplete/.test(line)) this.incomplete++;
    if (/--- FAIL:|INTEGRITY_PHASE_FAILED/.test(line) && this.failures.length < 40) this.failures.push(line.trim());
    if (/body did not recover:/.test(line)) this.notes.add('Recovery body check failed; separate from TCP integrity.');
    if (/alignment did not recover:/.test(line)) this.notes.add('Recovery alignment check failed; not the reported body flake.');
    if (/throughput regression tcp_8_MBps:/.test(line)) this.notes.add('TCP eight-stream throughput gate failed; not a payload mismatch.');
    const pos = line.indexOf('WINTUN_RESULT ');
    if (pos < 0) return;
    let r;
    try { r = JSON.parse(line.slice(pos + 14)); } catch { this.incomplete++; return; }
    if (r.verdict === 'integrity_failure' || r.test === 'tcp_integrity_first_failure' || r.test === 'tcp_payload_difference') this.corruption++;
    if (r.verdict === 'diagnostic_incomplete') this.incomplete++;
    if (r.test === 'integrity_overhead' && r.verdict === 'diagnostic_overhead_exceeded') {
      const failure = {boundary:r.boundary, mode:r.mode, ratio:r.median_diagnostic_over_clean, minimum_ratio:r.minimum_ratio};
      this.overheadFailures.push(failure);
      this.notes.add(`Diagnostic overhead gate: ${r.boundary}/${r.mode}, ratio ${r.median_diagnostic_over_clean.toFixed(6)} < ${r.minimum_ratio}. No byte mismatch is implied.`);
    }
    if (r.test === 'tcp_integrity') this.connections++;
    if (r.test === 'performance_sample' && r.sample?.status === 'invalid' && r.sample?.metric === 'udp_8_MBps' && r.sample?.error === 'The data is invalid.') {
      this.notes.add('DLL/host UDP sample returned invalid data; not the reported throughput-gap flake.');
    }
  }
  result(code) {
    const verdict = this.corruption ? 'integrity_failure' : this.incomplete ? 'diagnostic_incomplete' : this.timeouts ? 'diagnostic_timeout' : this.overheadFailures.length ? 'diagnostic_overhead_exceeded' : code !== 0 ? 'test_failed' : !this.complete ? 'diagnostic_incomplete' : 'no_corruption_observed';
    return {verdict, exit: code || (verdict === 'no_corruption_observed' ? 0 : 1), diagnostic_connections: this.connections,
      integrity_evidence_records: this.corruption, incomplete_records: this.incomplete, failed_overhead_gates:this.overheadFailures, notes: [...this.notes], failed_tests_and_phases: this.failures};
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  if (process.env.GITHUB_ACTIONS !== 'true' || process.env.RUNNER_ENVIRONMENT !== 'github-hosted') throw Error('Hosted CI only');
  const child = spawn('pwsh', ['-NoProfile','-File','scripts/test-wintun-integrity.ps1',
    '-Repeats',process.env.INTEGRITY_REPEATS,'-Scenario',process.env.INTEGRITY_SCENARIO,'-Arch',process.env.RUNNER_ARCH],
    {stdio:['ignore','pipe','pipe'],windowsHide:true});
  const summary = new IntegritySummary();
  // Both streams stay visible in the Actions log, including all bounded packet
  // evidence. Only the summary is retained here; no downloaded log file.
  for (const stream of [child.stdout, child.stderr]) {
    createInterface({input:stream}).on('line', line => { process.stdout.write(`${line}\n`); summary.line(line); });
  }
  child.on('error', error => { console.error(error.message); process.exitCode = 1; });
  child.on('close', code => {
    const result = summary.result(code ?? 1);
    console.log(`INTEGRITY_SUMMARY ${JSON.stringify(result)}`);
    if (process.env.GITHUB_STEP_SUMMARY) appendFileSync(process.env.GITHUB_STEP_SUMMARY,
      `### TCP integrity: ${result.verdict}\n\nDiagnostic connection records: ${result.diagnostic_connections}. Full boundary evidence remains in the job log.\n\n` +
      [...result.notes, ...result.failed_tests_and_phases].map(line => `- ${line.replaceAll('<','&lt;')}\n`).join('') +
      '\nOther test failures retain their failed exit status; no samples were retried or replaced. A clean hunt does not clear the release blocker.\n');
    process.exitCode = result.exit;
  });
}
