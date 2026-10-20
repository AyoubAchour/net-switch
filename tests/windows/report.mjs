import { writeFile } from 'node:fs/promises';

export class BaselineDefect extends Error {
  constructor(message, evidence) { super(message); this.evidence = evidence; }
}

export class Report {
  constructor(profile, progressFile) { this.profile = profile; this.results = []; this.progressFile = progressFile; }
  async test(name, label, fn) {
    if (!['harness-baseline', 'parity', 'baseline-defect'].includes(label)) throw new Error(`Missing label: ${name}`);
    const started = performance.now();
    const parent = this.running;
    this.running = { name, label, startedAt: new Date().toISOString() };
    await this.checkpoint();
    try {
      const evidence = await fn();
      if (label === 'baseline-defect' && this.profile === 'baseline') {
        const error = new Error(`Baseline defect no longer reproduces: ${name}. Review the executable pin and classification.`);
        error.defectNotReproduced = true;
        error.evidence = evidence;
        throw error;
      }
      this.results.push({ name, label, status: 'pass', ms: performance.now() - started, evidence });
      console.log(`PASS [${label}] ${name}`);
      return evidence;
    } catch (error) {
      const known = label === 'baseline-defect' && error instanceof BaselineDefect;
      this.results.push({ name, label, status: error.defectNotReproduced ? 'defect-not-reproduced' : known ? 'confirmed-defect' : 'fail', ms: performance.now() - started,
        error: error.stack, evidence: error.evidence });
      console.error(`${known ? 'BASELINE DEFECT' : 'FAIL'} [${label}] ${name}: ${error.message}`);
      if (error.evidence) console.error(`FAIL EVIDENCE ${JSON.stringify({ name, evidence: error.evidence })}`);
      if (!known || this.profile !== 'baseline') throw error;
    } finally {
      this.running = parent;
      await this.checkpoint();
    }
  }
  deferred(name, milestone, reason) { this.results.push({ name, label: 'parity', status: 'deferred', milestone, reason }); }
  pendingMilestone(name, milestone, reason) {
    if (![2, 5].includes(milestone)) throw new Error('Only lifecycle and installer work may be pending in the engine profile');
    this.results.push({ name, label: 'parity', status: 'pending-milestone', milestone, reason });
  }
  async save(file) {
    const counts = this.results.reduce((all, { label, status }) => {
      const group = all[label] ??= {};
      group[status] = (group[status] ?? 0) + 1;
      return all;
    }, {});
    console.log(`CASE COUNTS ${JSON.stringify({ architecture: process.arch, counts })}`);
    await this.checkpoint(file, true);
  }
  async checkpoint(file = this.progressFile, complete = false) {
    if (!file) return;
    const releaseReady = complete && !this.results.some(({ status }) => status !== 'pass');
    const oldV1WouldPass = releaseReady;
    await writeFile(file, JSON.stringify({ profile: this.profile, architecture: process.arch, complete, running: this.running,
      releaseReady, oldV1WouldPass, results: this.results }, null, 2));
  }
}
