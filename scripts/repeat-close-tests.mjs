// Keep all 1,000 repetitions, but release race-detector process memory between
// batches. Every named case must actually run and pass in every batch.
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { createInterface } from 'node:readline';
import { pathToFileURL } from 'node:url';

const groups = {
  TimeWait: ['BlockedAndBudgetReuse', 'FinalACKReleasesAdmission', 'LostFinalACK', 'SYNBetweenRemovalAndHook', 'LateHookDoesNotReadmitLiveFlow', 'ClosingQueue', 'SYNBeforeCloseState', 'SYNBeforeRemoval', 'ZeroCapClosingBatch'],
  Close: ['Admission', 'IdleAdmission', 'FINWithoutPolicy', 'KeepsQueuedDataCounted', 'RSTDuringHandshake', 'BeforeFinalACK', 'HandshakeCap', 'RetainedCap', 'RetainedCapLostFIN', 'UnknownACKGetsReset', 'HandshakeCompletionOwnsRelease', 'HandshakeBeforeHangupNotification', 'FencePreservesListenerProcessing', 'FenceWakesRemainingSegments'],
};
const parents = Object.entries(groups).flatMap(([prefix, names]) => names.map(name => `Test${prefix}${name}`));
const required = [...parents, 'TestCloseHandshakeCap/1', 'TestCloseHandshakeCap/2048', 'TestCloseRetainedCap/simultaneous_false', 'TestCloseRetainedCap/simultaneous_true'];

export class Results {
  constructor(names = required) {
    this.cases = new Map(names.map(name => [name, { run: 0, pass: 0 }]));
    this.problems = [];
  }
  record(event) {
    if (event.Action === 'fail' || event.Action === 'skip') this.problems.push(`${event.Test || 'package'}: ${event.Action}`);
    const counts = this.cases.get(event.Test);
    if (counts && (event.Action === 'run' || event.Action === 'pass')) counts[event.Action]++;
  }
  verify(count) {
    assert.deepEqual(this.problems, [], 'failed or skipped repeat cases');
    for (const [name, result] of this.cases) {
      assert.equal(result.run, count, `${name}: run count`);
      assert.equal(result.pass, count, `${name}: pass count`);
    }
  }
}

// Include the actual test executable, not just its small `go test` parent.
// Read only this command's process tree; nothing is stopped or reconfigured.
function rssKiB(pid) {
  if (process.platform !== 'linux') return null;
  try {
    const status = readFileSync(`/proc/${pid}/status`, 'utf8');
    let rss = Number(status.match(/^VmRSS:\s+(\d+)/m)?.[1] || 0);
    const children = readFileSync(`/proc/${pid}/task/${pid}/children`, 'utf8').trim();
    for (const child of children ? children.split(/\s+/) : []) rss += rssKiB(Number(child)) || 0;
    return rss;
  } catch (err) {
    if (err.code === 'ENOENT' || err.code === 'ESRCH') return 0;
    throw err;
  }
}

async function batch(index, batches, count, race) {
  const results = new Results();
  const args = ['test', '-json', '-failfast', `-count=${count}`, '-timeout=5m', '-run', `^(${parents.join('|')})$`, './internal/engine/stack'];
  if (race) args.splice(1, 0, '-race');
  console.log(`CLOSE REPEAT batch ${index}/${batches}: ${count} repetitions; race=${race}`);
  const child = spawn(process.env.GO_BINARY || 'go', args, { stdio: ['ignore', 'pipe', 'inherit'], windowsHide: true });
  const exited = new Promise((resolve, reject) => {
    child.once('error', reject);
    child.once('close', (code, signal) => resolve({ code, signal }));
  });
  let peakRSS = 0;
  const monitor = setInterval(() => {
    const rss = rssKiB(child.pid);
    if (rss !== null) {
      peakRSS = Math.max(peakRSS, rss);
      const available = readFileSync('/proc/meminfo', 'utf8').match(/^MemAvailable:\s+(\d+)/m)?.[1];
      console.log(`CLOSE REPEAT memory batch ${index}: RSS=${rss} KiB peak=${peakRSS} KiB host-available=${available} KiB; full-cap passes=${results.cases.get('TestCloseHandshakeCap/2048').pass}`);
    }
  }, 10_000);
  let parseError;
  try {
    const lines = createInterface({ input: child.stdout, crlfDelay: Infinity });
    for await (const line of lines) {
      try {
        const event = JSON.parse(line);
        if (event.Output) process.stdout.write(event.Output);
        results.record(event);
      } catch (err) {
        parseError ||= err;
      }
    }
    const { code, signal } = await exited;
    assert.ifError(parseError);
    assert.equal(code, 0, `batch ${index}: code=${code} signal=${signal}`);
    results.verify(count);
    console.log(`CLOSE REPEAT batch ${index}/${batches} verified: ${count} passes for every required case; sampled peak RSS=${process.platform === 'linux' ? `${peakRSS} KiB` : 'unavailable'}`);
  } finally {
    clearInterval(monitor);
  }
}

async function main() {
  const args = process.argv.slice(2);
  assert.ok(args.every(a => a === '--race' || /^--(count|batches)=\d+$/.test(a)), 'unknown repeat option');
  const number = (name, fallback) => Number(args.find(a => a.startsWith(`--${name}=`))?.split('=')[1] || fallback);
  const count = number('count', 100), batches = number('batches', 10);
  assert.ok(count > 0 && batches > 0 && Number.isSafeInteger(count * batches), 'invalid repeat count');
  for (let i = 1; i <= batches; i++) await batch(i, batches, count, args.includes('--race'));
  console.log(`CLOSE REPEAT VERIFIED: ${count * batches} passes for every required case across ${batches} complete batches; no skipped or missing cases.`);
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  await main();
}
