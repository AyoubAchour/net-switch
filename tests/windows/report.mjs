import { writeFile } from 'node:fs/promises';

export class BaselineDefect extends Error {
  constructor(message, evidence) { super(message); this.evidence = evidence; }
}

export class Report {
  constructor(profile) { this.profile = profile; this.results = []; }
  async test(name, label, fn) {
    if (!['parity', 'baseline-defect'].includes(label)) throw new Error(`Missing label: ${name}`);
    const started = performance.now();
    try {
      const evidence = await fn();
      this.results.push({ name, label, status: 'pass', ms: performance.now() - started, evidence });
      console.log(`PASS [${label}] ${name}`);
      return evidence;
    } catch (error) {
      const known = label === 'baseline-defect' && error instanceof BaselineDefect;
      this.results.push({ name, label, status: known ? 'confirmed-defect' : 'fail', ms: performance.now() - started,
        error: error.stack, evidence: error.evidence });
      console.error(`${known ? 'BASELINE DEFECT' : 'FAIL'} [${label}] ${name}: ${error.message}`);
      if (!known || this.profile !== 'baseline') throw error;
    }
  }
  deferred(name, milestone, reason) { this.results.push({ name, label: 'parity', status: 'deferred', milestone, reason }); }
  async save(file) {
    await writeFile(file, JSON.stringify({ profile: this.profile, architecture: process.arch, results: this.results }, null, 2));
  }
}
