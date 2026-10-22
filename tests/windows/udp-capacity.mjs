import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import { copyFile } from 'node:fs/promises';
import path from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import { hostedOnly, run, until } from './testisp/harness.mjs';
import { captureHeap } from './heap-profile.mjs';

export async function nativeUDPCapacity(binding) {
  hostedOnly();
  const result = await run(path.resolve('dist/windows-test/windows-platform.test.exe'),
    ['-test.v', '-test.run=^TestNativeUDPSocketCapacity$', '-test.timeout=1m'],
    { env: { NETSWITCH_PORT_GATE: '1' } });
  const marker = 'WINDOWS NATIVE UDP CAPACITY ';
  const line = result.stdout.split(/\r?\n/).find((value) => value.includes(marker));
  assert(line, result.stdout);
  const native = JSON.parse(line.slice(line.indexOf(marker) + marker.length));
  assert(native.held > 0 && native.uniquePorts === native.held && Object.keys(native.failures).length);
  // The Go pair variant also runs the native control for UDP recovery: the
  // engine run's release/reopen cycle with the engine out of the path.
  const paired = await run(path.resolve('dist/windows-test/windows-platform.test.exe'),
    ['-test.v', '-test.run=^TestNativeUDPPairedCapacity$', '-test.timeout=10m'],
    { env: { NETSWITCH_PORT_GATE: '1', NETSWITCH_UDP_BASELINE_SOURCE: binding.address,
      NETSWITCH_UDP_BASELINE_INDEX: String(binding.index), NETSWITCH_UDP_RECOVERY_CYCLES: String(udpRecoveryCycles) },
    timeout: 600_000 });
  const cyclesMarker = 'WINDOWS NATIVE UDP RECOVERY CYCLES ';
  // Two native controls: plain sockets, and engine halves through the
  // engine's readiness path (native duplicate and event registration).
  const nativeRecovery = paired.stdout.split(/\r?\n/).filter((value) => value.includes(cyclesMarker))
    .map((value) => JSON.parse(value.slice(value.indexOf(cyclesMarker) + cyclesMarker.length)));
  // Four with cycles: plain Go, plain Go under TCP load, the engine's native
  // socket registered for readiness, and the same socket not registered.
  assert(udpRecoveryCycles === 0 || (nativeRecovery.length === 4 && nativeRecovery.every((item) => item.cycles?.length === udpRecoveryCycles)),
    `Native UDP recovery controls did not run: ${paired.stdout.slice(-2000)}`);
  for (const item of nativeRecovery) {
    const path = item.readyUDP ? `native, ${item.engineSocket}` : item.tcpLoad ? `native, TCP corner held (${item.tcpLoad} TCP clients)` : 'native';
    console.log(`WINDOWS UDP RECOVERY RATE ${JSON.stringify({ path, cycles: item.cycles.length,
      attempts: item.reopenAttempts, refused: item.reopenRefused,
      restoreRefused: item.cycles.reduce((n, cycle) => n + cycle.restoreRefused, 0),
      refusals: item.cycles.flatMap((cycle) => cycle.refusals ?? []) })}`);
  }
  const pairMarker = 'WINDOWS NATIVE UDP PAIRED CAPACITY ';
  const pairs = paired.stdout.split(/\r?\n/).filter((value) => value.includes(pairMarker))
    .map((value) => JSON.parse(value.slice(value.indexOf(pairMarker) + pairMarker.length)));
  // Go and ReadyUDP always; the unregistered Constructor variant with cycles.
  assert.equal(pairs.length, udpRecoveryCycles > 0 ? 3 : 2, 'The Go and ReadyUDP matched baselines must run');
  for (const sample of pairs) {
    assert.equal(sample.source, binding.address);
    assert.equal(sample.interfaceIndex, binding.index);
    assert(sample.heldPairs > 0 && sample.echoedDatagrams === sample.heldPairs * 2);
  }
  console.log(`WINDOWS MATCHED UDP BASELINE ${JSON.stringify({ legacy: native, pairs })}`);
  const concurrent = await run(path.resolve('dist/windows-test/windows-platform.test.exe'),
    ['-test.v', '-test.run=^TestNativeUDPConcurrentPairedCapacity$', '-test.timeout=3m'],
    { env: { NETSWITCH_PORT_GATE: '1', NETSWITCH_UDP_BASELINE_SOURCE: binding.address,
      NETSWITCH_UDP_BASELINE_INDEX: String(binding.index) }, timeout: 180_000 });
  const concurrentMarker = 'WINDOWS NATIVE UDP CONCURRENT PAIRED CAPACITY ';
  const concurrentPairs = concurrent.stdout.split(/\r?\n/).filter((value) => value.includes(concurrentMarker))
    .map((value) => JSON.parse(value.slice(value.indexOf(concurrentMarker) + concurrentMarker.length)));
  assert.equal(concurrentPairs.length, 2, 'Both concurrent native baselines must run');
  for (const sample of concurrentPairs) {
    assert.equal(sample.concurrency, 32);
    assert.equal(sample.source, binding.address);
    assert.equal(sample.interfaceIndex, binding.index);
    assert(sample.limitReached && sample.verifiedPayloads === sample.heldPairs * 2);
  }
  console.log(`WINDOWS CONCURRENT UDP BASELINE ${JSON.stringify(concurrentPairs)}`);
  return { ...native, matchedPairs: pairs, concurrentPairs, nativeRecovery };
}

// Release/reopen cycles for the UDP recovery rates (SYSTEM-DESIGN 5.9 open
// question): the same count natively and through the engine, in one job.
export const udpRecoveryCycles = Number(process.env.NETSWITCH_UDP_RECOVERY_CYCLES ?? 10);

async function udpPortSpaceAtFailure() {
  const startedAt = new Date().toISOString();
  const result = await run(path.resolve('dist/windows-test/windows-platform.test.exe'),
    ['-test.v', '-test.run=^TestUDPPortSpaceDiagnosisReadsHostedSettings$', '-test.timeout=90s']);
  const marker = 'WINDOWS UDP PORT SPACE ';
  const line = result.stdout.split(/\r?\n/).find((value) => value.includes(marker));
  assert(line, result.stdout);
  return { requestedAt: startedAt, ...JSON.parse(line.slice(line.indexOf(marker) + marker.length)) };
}

// SYSTEM-DESIGN 5.9, "Windows port limit" (TCP and UDP alike, 2026-10-21):
// recovery counts a failed reopen only when the pool had room; a port another
// process took inside the window is reported. Reported means all of: every
// failure is a port-exhaustion error, the family's dynamic pool had no free
// port at the failure, and processes other than the clients and the engine
// grew by at least as many dynamic ports as there were failures. Anything
// else stays a failure. othersBefore/After map PID to dynamic UDP ports held
// by non-client processes, just before the reopen and at the failure.
export function udpRecoveryVerdict({ failures, portSpace, othersBefore, othersAfter, enginePID, family }) {
  const pool = (portSpace?.families ?? []).find((item) => item.family === family);
  const grownByOthers = Object.entries(othersAfter ?? {}).reduce((sum, [pid, ports]) =>
    Number(pid) === enginePID ? sum : sum + Math.max(0, ports - (othersBefore?.[pid] ?? 0)), 0);
  const portErrors = failures.length > 0 && failures.every((item) => ['ENOBUFS', 'EADDRINUSE'].includes(item.Error));
  const poolFull = portSpace?.state === 'complete' && pool?.available === 0;
  const reported = portErrors && poolFull && grownByOthers >= failures.length;
  return { oldVerdict: failures.length ? 'fail' : 'pass', newVerdict: failures.length ? (reported ? 'reported' : 'fail') : 'pass',
    grownByOthers, portErrors, poolFull, available: pool?.available ?? null };
}

// Held-session responsiveness (SYSTEM-DESIGN 5.9, decided 2026-10-21): at the
// UDP cap, one echo through every held session, 32 at a time, has p99 <= 250 ms
// and the whole sweep across every app finishes within 30 s.
export const heldUDPSweepGate = Object.freeze({ concurrency: 32, p99US: 250_000, sweepMS: 30_000 });
const latencyBoundsUS = [1_000, 2_000, 5_000, 10_000, 25_000, 50_000, 100_000, 250_000, 500_000, 1_000_000, 2_000_000];

// The capacity client hashes the 8-byte tokens of its held sessions in held
// order. The host keeps the same ledger, so a match names the swept population.
export function ledgerDigest(tokens) {
  const hash = createHash('sha256');
  for (const token of tokens) hash.update(Buffer.from(token, 'hex'));
  return hash.digest('hex');
}

// Nearest rank: the smallest value with at least perMille/1000 of the
// population at or below it. Censored sessions (failed or missing echoes) rank
// above every sample, so a rank that lands on one has no finite value.
function nearestRank(sorted, population, perMille) {
  if (!population) return null;
  const rank = Math.ceil(perMille * population / 1000);
  return rank <= sorted.length ? sorted[rank - 1] : null;
}

// apps: [{ app, expectedCount, expectedDigest, result?, error? }]. result is the
// client's verify reply, present even when it reported failed echoes.
export function heldSweepLatency({ held, sweepMS, apps }) {
  const samples = [], perApp = [], failures = {};
  let represented = 0, expected = 0, failed = 0;
  let complete = Number.isSafeInteger(held) && held > 0;
  const seenApps = new Set();
  for (const item of apps) {
    const result = item.result, values = Array.isArray(result?.samplesUS) ? result.samplesUS : [];
    const counts = result?.failures ?? {};
    const validCounts = typeof counts === 'object' && !Array.isArray(counts) &&
      Object.values(counts).every((count) => Number.isSafeInteger(count) && count >= 0);
    const appFailed = validCounts ? Object.values(counts).reduce((n, count) => n + count, 0) : 0;
    if (validCounts) {
      for (const [label, count] of Object.entries(counts)) failures[label] = (failures[label] ?? 0) + count;
    }
    const valid = values.every((value) => Number.isSafeInteger(value) && value > 0);
    const digestMatches = result?.heldDigest === item.expectedDigest;
    const whole = Boolean(result) && valid && validCounts && Number.isSafeInteger(appFailed) &&
      Number.isSafeInteger(item.expectedCount) && item.expectedCount >= 0 && !seenApps.has(item.app) &&
      digestMatches && result.checked === item.expectedCount &&
      result.echoed === values.length && values.length + appFailed === result.checked;
    seenApps.add(item.app);
    if (valid) samples.push(...values);
    expected += item.expectedCount;
    failed += appFailed;
    if (whole) represented += result.checked; else complete = false;
    perApp.push({ app: item.app, expected: item.expectedCount, checked: result?.checked ?? null,
      echoed: valid ? values.length : null, failed: appFailed, digestMatches, whole,
      maxUS: valid && values.length ? Math.max(...values) : null, clientSweepMS: result?.sweepMS ?? null,
      ...(item.error ? { error: item.error } : {}) });
  }
  samples.sort((a, b) => a - b);
  // Every held session is one member. Anything without an exact echo is censored.
  const population = Math.max(held, samples.length + failed);
  const censored = population - samples.length;
  const counts = latencyBoundsUS.map(() => 0);
  let over = 0;
  for (const value of samples) {
    const bucket = latencyBoundsUS.findIndex((bound) => value <= bound);
    if (bucket < 0) over++; else counts[bucket]++;
  }
  const quantilesUS = Object.fromEntries([['p50', 500], ['p90', 900], ['p99', 990], ['p999', 999]]
    .map(([name, perMille]) => [name, nearestRank(samples, population, perMille)]));
  const pass = {
    represented: complete && censored >= 0 && expected === held && represented === held,
    p99: quantilesUS.p99 !== null && quantilesUS.p99 <= heldUDPSweepGate.p99US,
    sweep: Number.isFinite(sweepMS) && sweepMS >= 0 && sweepMS <= heldUDPSweepGate.sweepMS,
  };
  pass.p99 &&= pass.represented;
  return {
    gate: heldUDPSweepGate, rank: 'nearest-rank over every held session; failed or missing echoes rank above all samples',
    held, population, echoed: samples.length, censored, failures,
    quantilesUS, p99MS: quantilesUS.p99 === null ? null : quantilesUS.p99 / 1000,
    minUS: samples[0] ?? null, maxUS: censored ? null : samples.at(-1) ?? null,
    histogram: { boundsUS: latencyBoundsUS, counts, over, censored },
    sweepMS, apps: perApp, pass, passed: pass.represented && pass.p99 && pass.sweep,
  };
}

async function client(server, directory, line, app) {
  const exe = path.join(directory, `udp-capacity-app-${app}.exe`);
  await copyFile(path.resolve('dist/windows-test/udpreject.exe'), exe);
  await server.api('app-line', { path: exe, line });
  const child = spawn(exe, ['--capacity'], { windowsHide: true, stdio: ['pipe', 'pipe', 'inherit'] });
  const pending = new Map(), commands = new Map();
  // Tokens the client holds, in its own held order, followed from every reply
  // (including replies that arrive after their call's deadline).
  const ledger = [];
  let serial = 0, buffer = '';
  const fail = (error) => {
    for (const item of pending.values()) { clearTimeout(item.timer); item.reject(error); }
    pending.clear();
  };
  child.once('error', fail);
  child.stdin.on('error', fail);
  child.once('exit', (code) => fail(new Error(`UDP capacity client ${app} exited ${code}`)));
  child.stdout.on('data', (chunk) => {
    buffer += chunk;
    for (;;) {
      const end = buffer.indexOf('\n');
      if (end < 0) break;
      const reply = JSON.parse(buffer.slice(0, end)); buffer = buffer.slice(end + 1);
      const command = commands.get(reply.id);
      commands.delete(reply.id);
      if (command === 'open') ledger.push(...(reply.result?.attempts ?? []).filter((item) => !item.Error).map((item) => item.Token));
      else if (command === 'release') ledger.splice(0, reply.result?.released ?? 0);
      else if (command === 'close') ledger.length = 0;
      const item = pending.get(reply.id);
      if (!item) continue;
      pending.delete(reply.id); clearTimeout(item.timer);
      // A failed command still reports what it measured.
      if (reply.error) item.reject(Object.assign(new Error(reply.error), { result: reply.result }));
      else item.resolve(reply.result);
    }
  });
  const call = (command, fields = {}) => new Promise((resolve, reject) => {
    const id = ++serial;
    commands.set(id, command);
    const started = performance.now();
    const startedAt = new Date().toISOString();
    const timer = setTimeout(() => { pending.delete(id); reject(new Error(`UDP ${app} ${command} deadline`)); }, 60_000);
    pending.set(id, { resolve: (result) => {
      const timing = { app, command, count: fields.count, startedAt, finishedAt: new Date().toISOString(),
        elapsedMS: performance.now() - started, held: result.held };
      console.log(`WINDOWS UDP COHORT PHASE ${JSON.stringify(timing)}`);
      resolve({ ...result, timing });
    }, reject, timer });
    child.stdin.write(JSON.stringify({ id, command, app, ...fields }) + '\n');
  });
  return { app, child, call, exe, ledger, admissions: [] };
}

export async function holdUDPCapacity({ server, harness, directory, line, native, evidence }) {
  hostedOnly();
  const target = await harness.control('udp-capacity', {});
  const clients = [];
  const engineStats = async () => (await server.api('engine-command', { method: 'stats' })).engine;
  const close = async () => {
    const errors = [];
    for (const app of clients) {
      if (app.child.exitCode === null) {
        try { await app.call('close'); } catch (error) { errors.push(error); } finally { app.child.stdin.end(); }
      }
    }
    await harness.control('udp-capacity-close', {});
    if (errors.length) throw new AggregateError(errors, 'UDP capacity cleanup failed');
  };
  const checkSource = (observed) => {
    assert.equal(observed.dropped, 0, 'The controlled UDP peer dropped a reply');
    assert.equal(observed.conflicts, 0, 'A held UDP mapping changed its physical source');
  };
  const observe = async () => {
    const observed = await harness.control('udp-capacity');
    checkSource(observed);
    return observed;
  };
  try {
    evidence.native = native;
    evidence.layoutCapacity = Math.floor(native.held / 2);
    evidence.floor = Math.ceil(evidence.layoutCapacity * 0.95);
    evidence.before = await engineStats();
    evidence.baselineHeap = await captureHeap(server, 'udp-baseline', 0, 0);
    evidence.oldRuntimeBudgetWouldPass = true;
    evidence.runtimePeakBytes = evidence.before.runtimeBytes;
    for (let i = 1; i <= 8; i++) clients.push(await client(server, directory, line, i));
    evidence.clientPIDs = clients.map((app) => ({ pid: app.child.pid, executable: app.exe }));
    let held = 0;
    const failed = [], attempts = [];
    while (!failed.length && held < 16384) {
      for (const app of clients) {
        const result = await app.call('open', { ...target, count: 128 });
        for (const attempt of result.attempts) {
          attempts.push(attempt);
          if (attempt.Error) failed.push(attempt);
          else { app.admissions.push(attempt); held++; }
        }
        assert(result.held <= 4096, 'UDP fixture exceeded the per-app cap');
        const stats = await engineStats();
        console.log(`WINDOWS UDP ADMISSION ${JSON.stringify({ held, flows: stats.flows, heapBytes: stats.heapBytes,
          stackBytes: stats.stackBytes, runtimeBytes: stats.runtimeBytes, goroutines: stats.goroutines, gcCPUppm: stats.gcCPUppm })}`);
        evidence.oldRuntimeBudgetWouldPass &&= stats.runtimeBytes <= 512 * 1024 * 1024;
        evidence.runtimePeakBytes = Math.max(evidence.runtimePeakBytes, stats.runtimeBytes);
        if (failed.length) {
          // Both halves allocate ports. Preserve the same-runner reservation
          // evidence even when the app fails before the engine sees a packet.
          Object.assign(evidence, { held, failed, attempts });
          evidence.portSpaceAtFailure = await udpPortSpaceAtFailure().catch((error) => ({ error: String(error) }));
          console.log(`WINDOWS UDP PORT SPACE AT FAILURE ${JSON.stringify(evidence.portSpaceAtFailure)}`);
          break;
        }
      }
    }
    Object.assign(evidence, { held, failed, attempts });
    const matched = native.matchedPairs.find((sample) => sample.readyUDP);
    evidence.floorVerdicts = { legacyLoopbackFloor: evidence.floor, legacyWouldPass: held >= evidence.floor,
      matchedPairFloor: Math.ceil(matched.heldPairs * 0.95),
      matchedWouldPass: held >= Math.ceil(matched.heldPairs * 0.95),
      appliedGate: 'legacy floor remains hard until excluded-range evidence explains the difference' };
    console.log(`WINDOWS UDP FLOOR VERDICTS ${JSON.stringify(evidence.floorVerdicts)}`);
    assert(failed.length, 'UDP fixture did not reach the native OS port limit');
    assert(failed.every((item) => ['ENOBUFS', 'EADDRINUSE', 'ECONNRESET', 'ECONNREFUSED'].includes(item.Error)),
      `UDP delivery loss or unrelated failure: ${JSON.stringify(failed)}`);
    assert(held >= evidence.floor, `UDP held ${held}, below the 95% native layout floor ${evidence.floor}`);
    assert.equal(evidence.portSpaceAtFailure.state, 'complete', 'The failed allocation lacks complete port-space evidence');
    const atLimit = await engineStats();
    if (failed.some((item) => ['ECONNRESET', 'ECONNREFUSED'].includes(item.Error))) {
      assert(atLimit.udpSocketExhaustions > evidence.before.udpSocketExhaustions,
        'A UDP refusal was not caused by native port exhaustion');
    }
    const observed = evidence.observed = await observe();
    assert.equal(Object.keys(observed.seen).length, held, 'Client/server UDP admission counts differ');
    for (const app of clients) for (const item of app.admissions) {
      assert(observed.seen[item.Token]?.startsWith('198.19.0.1:'), `UDP escaped TestISP: ${item.Token}`);
    }
    const records = [];
    let cursor = '';
    do {
      const page = await server.api('engine-command', { method: 'flows', fields: { cursor } });
      records.push(...page.flows.filter((flow) => flow.protocol === 'udp' && flow.destination === `${target.host}:${target.port}`));
      cursor = page.cursor ?? '';
    } while (cursor);
    const clientSources = new Set(clients.flatMap((app) => app.admissions.map((item) => item.Local)));
    const refusedSources = new Set(failed.map((item) => item.Local).filter(Boolean));
    const countsBySource = new Map();
    for (const record of records) countsBySource.set(record.source, (countsBySource.get(record.source) ?? 0) + 1);
    evidence.flowComparison = {
      clientHeld: held, serverHeld: Object.keys(observed.seen).length, engineRows: records.length,
      excess: records.filter((record) => !clientSources.has(record.source)).map((record) => ({
        ...record, sourceWasRefused: refusedSources.has(record.source),
      })),
      duplicateSources: [...countsBySource].filter(([, count]) => count > 1),
      missingClientSources: [...clientSources].filter((source) => !countsBySource.has(source)),
    };
    assert.equal(records.length, held, 'Client/server/engine UDP session counts differ');
    const bySource = new Map(records.map((flow) => [flow.source, flow]));
    for (const app of clients) for (const item of app.admissions) {
      const flow = bySource.get(item.Local);
      assert(flow && flow.line === line && flow.app.path.toLowerCase() === app.exe.toLowerCase(),
        `UDP session attribution mismatch: ${JSON.stringify({ item, flow })}`);
    }
    const checkStats = (stats) => {
      assert(stats.flows.UDP >= held, 'A held UDP session disappeared');
      evidence.oldRuntimeBudgetWouldPass &&= stats.runtimeBytes <= 512 * 1024 * 1024;
      evidence.runtimePeakBytes = Math.max(evidence.runtimePeakBytes, stats.runtimeBytes);
      assert(stats.goroutines < evidence.before.goroutines + 128, 'Idle sessions retained per-session workers');
      assert.equal(stats.tunDropped, evidence.before.tunDropped, 'TUN output dropped during the mixed cap');
      assert.equal(stats.udpDropped, evidence.before.udpDropped, 'UDP dropped during the mixed cap');
      assert.equal(stats.udpReadErrors, evidence.before.udpReadErrors, 'UDP reads failed during the mixed cap');
      assert.equal(stats.udpOversize, evidence.before.udpOversize, 'UDP packetization failed during the mixed cap');
      assert(stats.flows.UDPReplyBytes <= 8 * 1024 * 1024);
      assert(stats.flows.UDPReplyPeakBytes <= 8 * 1024 * 1024);
      assert(stats.tcpRelayBytes <= 16 * 1024 * 1024 && stats.tcpRelayPeakBytes <= 16 * 1024 * 1024,
        'The shared TCP relay exceeded its retained-buffer loan bound');
    };
    // Every check the old sweep made still runs, in the same order, beside the
    // held-session latency gate. All of them are evaluated and recorded before
    // any is thrown, so a failure keeps the old verdict and the latency evidence.
    const verify = async (label = `call-${(evidence.verificationPhases?.length ?? 0) + 1}`) => {
      const results = [], apps = [], failures = [];
      const check = (assertion) => {
        try { assertion(); return true; } catch (error) { failures.push(error); return false; }
      };
      const phase = { label, startedAt: new Date().toISOString(), results };
      (evidence.verificationPhases ??= []).push(phase);
      const sweepStarted = performance.now();
      // Apps stay in serial order, each sweeping with its own 32 workers. The
      // old sweep stopped at the first failed app; this one finishes every app.
      for (const app of clients) {
        const expected = { app: app.app, expectedCount: app.ledger.length, expectedDigest: ledgerDigest(app.ledger) };
        try {
          apps.push({ ...expected, result: await app.call('verify') });
        } catch (error) {
          const { result } = error;
          delete error.result; // The phase keeps its summary; the thrown error stays small.
          failures.push(error);
          apps.push({ ...expected, result, error: error.message });
        }
      }
      phase.sweepMS = performance.now() - sweepStarted;
      phase.finishedAt = new Date().toISOString();
      for (const { app, result } of apps) {
        if (!result) continue;
        const { samplesUS, ...summary } = result; // Per-echo samples are not retained.
        results.push({ app, ...summary });
      }
      const latency = heldSweepLatency({ held, sweepMS: phase.sweepMS, apps });
      apps.length = 0;
      const checkedSum = results.reduce((n, item) => n + (item.checked ?? 0), 0);
      const failedApps = latency.apps.filter((item) => item.error).map(({ app, error }) => ({ app, error }));
      const oldVerdict = phase.oldVerdict = { failedApps, oldStoppedAtApp: failedApps[0]?.app ?? null,
        checkedSum, held, maxMS: Math.max(0, ...results.map((item) => item.maxMS ?? 0)) };
      check(() => assert.equal(checkedSum, held));
      let stats, observed;
      try {
        stats = phase.stats = await engineStats();
        oldVerdict.statsPass = check(() => checkStats(stats));
      } catch (error) { failures.push(error); oldVerdict.statsPass = false; }
      try {
        observed = await harness.control('udp-capacity');
        oldVerdict.source = { dropped: observed.dropped, conflicts: observed.conflicts, pass: check(() => checkSource(observed)) };
      } catch (error) { failures.push(error); oldVerdict.source = { error: error.message, pass: false }; }
      oldVerdict.wouldPass = failures.length === 0;
      phase.latency = latency;
      check(() => assert(latency.pass.represented,
        `Held UDP latency population does not cover every held session: ${JSON.stringify(latency.apps)}`));
      check(() => assert(latency.pass.p99,
        `Held UDP echo p99 ${latency.p99MS ?? 'censored'} ms over ${latency.population} sessions ` +
        `(${latency.censored} censored) misses the ${heldUDPSweepGate.p99US / 1000} ms gate or its full population`));
      check(() => assert(latency.pass.sweep,
        `Held UDP full sweep took ${Math.round(latency.sweepMS)} ms, over ${heldUDPSweepGate.sweepMS} ms`));
      console.log(`WINDOWS UDP HELD SWEEP ${JSON.stringify({ label, startedAt: phase.startedAt, finishedAt: phase.finishedAt,
        oldVerdict, latency, results })}`);
      if (failures.length === 1) throw failures[0];
      if (failures.length) throw new AggregateError(failures, failures.map((error) => error.message).join('; '));
      return { results, stats, observed, oldVerdict, latency };
    };
    evidence.heldPlateau = [];
    evidence.verifiedBefore = await verify('before-gc');
    for (let i = 0; i < 3; i++) {
      const stats = await engineStats();
      checkStats(stats);
      evidence.heldPlateau.push(stats);
    }
    evidence.heldHeap = await captureHeap(server, 'udp-held', 0, held, evidence.baselineHeap);
    evidence.verifiedAfterGC = await verify('after-gc');
    const last = evidence.heldPlateau.at(-1), before = evidence.before;
    evidence.memoryPerSession = {
      ...evidence.heldHeap.perFlow, gcCPUppm: evidence.heldHeap.gcCPUppm,
      collection: 'immediately after forced GC',
      oldUncollectedHeapBytes: (last.heapBytes - before.heapBytes) / held,
      oldUncollectedStackBytes: (last.stackBytes - before.stackBytes) / held,
      oldUncollectedManagedBytes: (last.runtimeBytes - before.runtimeBytes) / held,
    };
    // Release/reopen cycles for the UDP recovery rates. Free ports come from
    // the engine's native UDP table, minus the excluded ranges read once.
    const cycleFamily = target.host.includes(':') ? 'ipv6' : 'ipv4';
    let cyclePool;
    const freeFrom = async (stats) => {
      cyclePool ??= (await udpPortSpaceAtFailure().catch(() => ({}))).families?.find((item) => item.family === cycleFamily);
      if (!cyclePool?.dynamicRange || !stats.nativeUDPState?.groups) return null;
      const used = new Set(stats.nativeUDPState.groups.filter((group) => !group.source.includes(':')).flatMap((group) => group.ports));
      let free = 0;
      for (let port = cyclePool.dynamicRange.start; port <= cyclePool.dynamicRange.end; port++) {
        if (!used.has(port) && !(cyclePool.excludedRanges ?? []).some((range) => port >= range.start && port <= range.end)) free++;
      }
      return free;
    };
    const refusalsOf = async (phase, attempts) => {
      const refused = attempts.filter((item) => item.Error);
      if (!refused.length) return [];
      const stats = await engineStats().catch(() => ({}));
      const free = await freeFrom(stats);
      // ECONNRESET here is the engine's own port unreachable after a failed
      // outbound send; its Winsock error is in udpSendFailures.
      console.log(`WINDOWS UDP RECOVERY SEND FAILURES ${JSON.stringify({ phase, refused: refused.length,
        sendFailures: stats.udpSendFailures, udpOpenFailed: stats.udpOpenFailed, udpSocketExhaustions: stats.udpSocketExhaustions })}`);
      await delay(200);
      const retry = await clients[0].call('open', { ...target, count: refused.length }).catch((error) => ({ error: String(error), attempts: [] }));
      const retried = retry.attempts ?? [];
      held += retried.filter((item) => !item.Error).length;
      return refused.map((item, i) => ({ phase, code: item.Error, errno: item.NativeCode, call: item.NativeCall,
        freeAfterBatch: free, retryAfter200msOK: retried[i] ? !retried[i].Error : false, retryCode: retried[i]?.Error || retry.error }));
    };
    // Evidence only, never gated: release 512, wait for the reconciliation,
    // reopen 256, restore 256, count times; then print one rate line.
    const evidenceCycles = async (count, label, cycles = []) => {
      for (let n = 0; n < count; n++) {
        const cycleBefore = await engineStats();
        const freed = await clients[0].call('release', { count: 512 });
        held -= freed.released;
        // Evidence only: a slow reconciliation is recorded, never fatal here
        // (the gated recovery keeps its own strict wait).
        const reconciled = await until(async () => (await engineStats()).flows.UDP <= cycleBefore.flows.UDP - freed.released,
          'UDP sessions released before an evidence cycle', 3000).then(() => true, () => false);
        const freeBeforeReopen = await freeFrom(await engineStats());
        const reopened = await clients[0].call('open', { ...target, count: 256 });
        held += reopened.attempts.filter((item) => !item.Error).length;
        const reopenRefusals = await refusalsOf('reopen', reopened.attempts);
        const restored = await clients[0].call('open', { ...target, count: 256 });
        held += restored.attempts.filter((item) => !item.Error).length;
        const restoreRefusals = await refusalsOf('restore', restored.attempts);
        cycles.push({ releasedPairs: freed.released, reconciled, freeBeforeReopen, reopenAttempts: 256, reopenRefused: reopenRefusals.length,
          restoreAttempts: 256, restoreRefused: restoreRefusals.length, refusals: [...reopenRefusals, ...restoreRefusals] });
      }
      console.log(`WINDOWS UDP RECOVERY RATE ${JSON.stringify({ path: label, cycles: cycles.length,
        attempts: cycles.reduce((n, cycle) => n + cycle.reopenAttempts, 0), refused: cycles.reduce((n, cycle) => n + cycle.reopenRefused, 0),
        restoreRefused: cycles.reduce((n, cycle) => n + (cycle.restoreRefused ?? 0), 0), refusals: cycles.flatMap((cycle) => cycle.refusals) })}`);
      return cycles;
    };
    return {
      checkStats, verify, close,
      // The matched comparison with the native control: same cycles, UDP
      // held at the limit, no TCP load, so only the engine differs.
      evidenceCycles: (count) => evidenceCycles(count, 'engine, UDP only'),
      get held() { return held; },
      recover: async () => {
        const before = await engineStats();
        const released = await clients[0].call('release', { count: 512 });
        // Evidence only: other processes' dynamic UDP ports just before the
        // re-open, to compare with the moment a re-open fails.
        const othersBeforeReopen = (stats) => {
          const clientPIDs = new Set((evidence.clientPIDs ?? []).map((item) => item.pid));
          const byPID = {};
          for (const group of stats.nativeUDPState?.groups ?? []) {
            if (!clientPIDs.has(group.pid)) byPID[group.pid] = (byPID[group.pid] ?? 0) + group.ports.filter((port) => port >= 49152).length;
          }
          return byPID;
        };
        const enginePID = before.nativeSocketState?.pid;
        assert.equal(released.released, 512);
        held -= 512;
        const started = performance.now();
        const reconciled = await until(async () => {
          const stats = await engineStats();
          return stats.flows.UDP <= before.flows.UDP - 512 && stats;
        }, 'UDP native ports and sessions released by the one-second reconciliation', 3000);
        const preReopen = othersBeforeReopen(await engineStats().catch(() => ({})));
        // Like TCP recovery, release 512 and reopen 256. Reopening all 512
        // put the pool back exactly at the OS limit, so any transient socket
        // elsewhere failed one reopen (ARM64 run 39614744644: app-side
        // ENOBUFS with no other process grown). With half reopened, the pool
        // must have room for every reopen and its engine socket; that is
        // read here and required, so a later failure is the engine's.
        const reopen = 256, family = target.host.includes(':') ? 'ipv6' : 'ipv4';
        const poolBefore = await udpPortSpaceAtFailure().catch((error) => ({ error: String(error) }));
        const availableBefore = poolBefore.families?.find((item) => item.family === family)?.available;
        console.log(`WINDOWS UDP RECOVERY POOL ${JSON.stringify({ released: 512, reopen, availableBefore, state: poolBefore.state })}`);
        assert(availableBefore >= 2 * reopen, `Released UDP ports did not return to the pool: ${availableBefore} free before reopening ${reopen}`);
        const returned = await clients[0].call('open', { ...target, count: reopen });
        const failures = returned.attempts.filter((item) => item.Error);
        if (failures.length) {
          // Evidence only: who held the dynamic ports when a re-open failed
          // (ARM64 853e295: 1 of 512 app-side ENOBUFS). The check is unchanged.
          const [portSpace, stats] = await Promise.all([
            udpPortSpaceAtFailure().catch((error) => ({ error: String(error) })),
            engineStats().catch((error) => ({ error: String(error) })),
          ]);
          // Dynamic-range UDP ports per process; the engine is the largest
          // non-client holder. Client processes are summed separately.
          const clientPIDs = new Set((evidence.clientPIDs ?? []).map((item) => item.pid));
          const owners = { clients: 0, byPID: {} };
          for (const group of stats.nativeUDPState?.groups ?? []) {
            const dynamic = group.ports.filter((port) => port >= 49152).length;
            if (clientPIDs.has(group.pid)) owners.clients += dynamic;
            else owners.byPID[group.pid] = (owners.byPID[group.pid] ?? 0) + dynamic;
          }
          const verdict = udpRecoveryVerdict({ failures, portSpace, othersAfter: owners.byPID, othersBefore: preReopen, enginePID, family });
          evidence.recoveryFailure = { failures, portSpace, dynamicPortOwners: owners, nonClientPortsBeforeReopen: preReopen, engineUDP: stats.flows?.UDP,
            heldBeforeReopen: held, socketExhaustions: stats.udpSocketExhaustions, enginePID, ...verdict };
          console.log(`WINDOWS UDP RECOVERY FAILURE ${JSON.stringify(evidence.recoveryFailure)}`);
          if (verdict.newVerdict === 'reported') {
            console.log(`WINDOWS UDP RECOVERY CONTENTION REPORTED ${JSON.stringify({ failures: failures.length, ...verdict })}`);
          }
        }
        held += reopen - failures.length;
        // The rate evidence (SYSTEM-DESIGN 5.9 open question): this gated
        // cycle plus evidence-only cycles of the same shape, here with the TCP
        // corner held. The matched comparison with the native control is the
        // UDP-only set run before any TCP load (evidenceCycles). Retries are
        // separate attempts and never change the gated verdict below.
        const gated = { gated: true, freeBeforeReopen: availableBefore, reopenAttempts: reopen, reopenRefused: failures.length,
          refusals: await refusalsOf('reopen', returned.attempts) };
        evidence.recoveryCycles = await evidenceCycles(udpRecoveryCycles - 1, 'engine, TCP corner held', [gated]);
        console.log(`WINDOWS UDP RECOVERY VERDICT ${JSON.stringify({ reopened: reopen - failures.length, failed: failures.length,
          oldVerdict: failures.length ? 'fail' : 'pass', newVerdict: failures.length ? evidence.recoveryFailure.newVerdict : 'pass' })}`);
        // The gate, unchanged: the first cycle's reopens, before any retry.
        if (failures.length && evidence.recoveryFailure.newVerdict !== 'reported') {
          assert.equal(failures.length, 0, `UDP capacity did not recover on first attempts: ${JSON.stringify(failures)}`);
        }
        evidence.recovery = { released, reconciled, returned, reopen, availableBefore, ms: performance.now() - started, verified: await verify('after-recovery') };
      },
    };
  } catch (error) {
    evidence.failedStats = await engineStats().catch(String);
    // Preserve the peer's actual failure evidence. Re-running the asserting
    // observer here would replace its source-change records with an error string.
    evidence.failedObserved = await harness.control('udp-capacity').catch(String);
    await close().catch((failure) => { evidence.cleanupError = failure.stack; });
    throw error;
  }
}

// The old 12,000-byte parity checks remain unchanged. These add the exact
// protocol maxima and prove both physical and app-side source addresses.
export async function largeUDPReplies({ server, harness, directory, line }) {
  hostedOnly();
  const target = await harness.control('udp-capacity', {});
  let app;
  const replies = [];
  const stats = async () => (await server.api('engine-command', { method: 'stats' })).engine;
  const before = await stats();
  try {
    app = await client(server, directory, line, 9);
    for (const [host, sizes, source] of [
      [target.host, [12000, 65506, 65507], '198.19.0.1:'],
      [target.host6, [12000, 65526, 65527], '2001:db8:19::1:'],
    ]) {
      for (const size of sizes) for (let repeat = 0; repeat < 3; repeat++) {
        const result = await app.call('open', { host, port: target.port, size, count: 1 });
        const reply = result.attempts[0];
        assert.equal(reply.Error, '', JSON.stringify(reply));
        assert.equal(reply.ReplyBytes, size);
        const token = Buffer.from(reply.Token, 'hex'), payload = Buffer.alloc(size);
        for (let i = 0; i < size; i++) payload[i] = ((i * 37 + 11) & 255) ^ token[i % 8];
        assert.equal(reply.SHA256, createHash('sha256').update(payload).digest('hex'));
        assert(!reply.Local.startsWith('198.19.0.1:') && !reply.Local.startsWith('[2001:db8:19::1]:'),
          `App bypassed the TUN: ${JSON.stringify(reply)}`);
        const observed = await harness.control('udp-capacity');
        assert(observed.seen[reply.Token]?.startsWith(source), `Large reply escaped its pinned line: ${JSON.stringify(observed)}`);
        assert.equal(observed.dropped, 0);
        replies.push(reply);
        assert.equal((await app.call('release', { count: 1 })).released, 1);
      }
    }
    const after = await stats();
    for (const key of ['tunDropped', 'udpDropped', 'udpOversize', 'udpReadErrors']) {
      assert.equal(after[key], before[key], `Large replies changed ${key}`);
    }
    console.log(`WINDOWS EXACT LARGE UDP REPLIES ${JSON.stringify({ replies, before, after })}`);
    return { replies, before, after };
  } finally {
    let closeError;
    if (app) {
      try { await app.call('close'); } catch (error) { closeError = error; } finally { app.child.stdin.end(); }
    }
    await harness.control('udp-capacity-close', {});
    // This app's own sessions are the ones to its target. The old check
    // compared the engine's total UDP count with the count before, so any
    // other process's UDP through the TUN failed it (ARM64 run 39559172829:
    // 17 of 18 gone, one session from elsewhere left). Keep its verdict.
    const targets = new Set([`${target.host}:${target.port}`, `[${target.host6}]:${target.port}`]);
    const udpFlows = async () => {
      const records = [];
      let cursor = '';
      do {
        const page = await server.api('engine-command', { method: 'flows', fields: { cursor } });
        records.push(...page.flows.filter((flow) => flow.protocol === 'udp'));
        cursor = page.cursor ?? '';
      } while (cursor);
      return records;
    };
    let last;
    const started = performance.now();
    try {
      await until(async () => {
        const [value, records] = await Promise.all([stats(), udpFlows()]);
        last = { value, records };
        // The engine's UDP counter must also equal the sessions it lists, so
        // a leaked count is still caught when another app's session is open.
        return records.every((flow) => !targets.has(flow.destination)) && value.flows.UDP === records.length &&
          value.flows.UDPReadBytes === 0 && value.flows.UDPReplyBytes === 0;
      }, 'large reply sessions and output leases released', 3000);
    } finally {
      const own = last?.records.filter((flow) => targets.has(flow.destination)) ?? null;
      console.log(`WINDOWS LARGE UDP RELEASE ${JSON.stringify({ ms: performance.now() - started,
        ownRemaining: own?.length ?? null, otherSessions: last?.records.filter((flow) => !targets.has(flow.destination)) ?? null,
        totalUDP: last?.value.flows.UDP ?? null, listedUDP: last?.records.length ?? null, totalBefore: before.flows.UDP,
        oldTotalCountWouldPass: last ? last.value.flows.UDP <= before.flows.UDP : null })}`);
    }
    if (closeError) throw closeError;
  }
}
