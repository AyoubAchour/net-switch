import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import { copyFile } from 'node:fs/promises';
import path from 'node:path';
import { hostedOnly, run, until } from './testisp/harness.mjs';
import { captureHeap } from './heap-profile.mjs';

export async function nativeUDPCapacity() {
  hostedOnly();
  const result = await run(path.resolve('dist/windows-test/windows-platform.test.exe'),
    ['-test.v', '-test.run=^TestNativeUDPSocketCapacity$', '-test.timeout=1m'],
    { env: { NETSWITCH_PORT_GATE: '1' } });
  const marker = 'WINDOWS NATIVE UDP CAPACITY ';
  const line = result.stdout.split(/\r?\n/).find((value) => value.includes(marker));
  assert(line, result.stdout);
  const native = JSON.parse(line.slice(line.indexOf(marker) + marker.length));
  assert(native.held > 0 && native.uniquePorts === native.held && Object.keys(native.failures).length);
  return native;
}

async function client(server, directory, line, app) {
  const exe = path.join(directory, `udp-capacity-app-${app}.exe`);
  await copyFile(path.resolve('dist/windows-test/udpreject.exe'), exe);
  await server.api('app-line', { path: exe, line });
  const child = spawn(exe, ['--capacity'], { windowsHide: true, stdio: ['pipe', 'pipe', 'inherit'] });
  const pending = new Map();
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
      const item = pending.get(reply.id);
      if (!item) continue;
      pending.delete(reply.id); clearTimeout(item.timer);
      if (reply.error) item.reject(new Error(reply.error)); else item.resolve(reply.result);
    }
  });
  const call = (command, fields = {}) => new Promise((resolve, reject) => {
    const id = ++serial;
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
  return { child, call, exe, admissions: [] };
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
  const observe = async () => {
    const observed = await harness.control('udp-capacity');
    assert.equal(observed.dropped, 0, 'The controlled UDP peer dropped a reply');
    assert.equal(observed.conflicts, 0, 'A held UDP mapping changed its physical source');
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
        if (failed.length) break;
      }
    }
    Object.assign(evidence, { held, failed, attempts });
    assert(failed.length, 'UDP fixture did not reach the native OS port limit');
    assert(failed.every((item) => ['ENOBUFS', 'EADDRINUSE', 'ECONNRESET', 'ECONNREFUSED'].includes(item.Error)),
      `UDP delivery loss or unrelated failure: ${JSON.stringify(failed)}`);
    assert(held >= evidence.floor, `UDP held ${held}, below the 95% native layout floor ${evidence.floor}`);
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
    const verify = async () => {
      const results = [];
      const phase = { startedAt: new Date().toISOString(), results };
      (evidence.verificationPhases ??= []).push(phase);
      for (const app of clients) {
        const result = await app.call('verify');
        results.push(result);
      }
      phase.finishedAt = new Date().toISOString();
      assert.equal(results.reduce((n, item) => n + item.checked, 0), held);
      const stats = await engineStats();
      checkStats(stats);
      return { results, stats, observed: await observe() };
    };
    evidence.heldPlateau = [];
    evidence.verifiedBefore = await verify();
    for (let i = 0; i < 3; i++) {
      const stats = await engineStats();
      checkStats(stats);
      evidence.heldPlateau.push(stats);
    }
    evidence.heldHeap = await captureHeap(server, 'udp-held', 0, held, evidence.baselineHeap);
    evidence.verifiedAfterGC = await verify();
    const last = evidence.heldPlateau.at(-1), before = evidence.before;
    evidence.memoryPerSession = {
      ...evidence.heldHeap.perFlow, gcCPUppm: evidence.heldHeap.gcCPUppm,
      collection: 'immediately after forced GC',
      oldUncollectedHeapBytes: (last.heapBytes - before.heapBytes) / held,
      oldUncollectedStackBytes: (last.stackBytes - before.stackBytes) / held,
      oldUncollectedManagedBytes: (last.runtimeBytes - before.runtimeBytes) / held,
    };
    return {
      checkStats, verify, close,
      get held() { return held; },
      recover: async () => {
        const before = await engineStats();
        const released = await clients[0].call('release', { count: 512 });
        assert.equal(released.released, 512);
        held -= 512;
        const started = performance.now();
        const reconciled = await until(async () => {
          const stats = await engineStats();
          return stats.flows.UDP <= before.flows.UDP - 512 && stats;
        }, 'UDP native ports and sessions released by the one-second reconciliation', 3000);
        const returned = await clients[0].call('open', { ...target, count: 512 });
        const failures = returned.attempts.filter((item) => item.Error);
        assert.equal(failures.length, 0, `UDP capacity did not recover on first attempts: ${JSON.stringify(failures)}`);
        held += 512;
        evidence.recovery = { released, reconciled, returned, ms: performance.now() - started, verified: await verify() };
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
    await until(async () => {
      const value = await stats();
      return value.flows.UDP <= before.flows.UDP && value.flows.UDPReadBytes === 0 && value.flows.UDPReplyBytes === 0;
    }, 'large reply sessions and output leases released', 3000);
    if (closeError) throw closeError;
  }
}
