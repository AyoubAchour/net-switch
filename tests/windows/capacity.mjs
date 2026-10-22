import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import { once } from 'node:events';
import { copyFile } from 'node:fs/promises';
import net from 'node:net';
import path from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import { hostedOnly, run, until } from './testisp/harness.mjs';
import { holdUDPCapacity, largeUDPReplies, nativeUDPCapacity, portRecoveryGate, udpRecoveryCycles } from './udp-capacity.mjs';
import { captureHeap } from './heap-profile.mjs';

async function nativeRefusalBaseline(host) {
  const listener = net.createServer();
  listener.listen(0, host);
  await once(listener, 'listening');
  const port = listener.address().port;
  await new Promise((resolve) => listener.close(resolve));
  return Promise.all(Array.from({ length: 3 }, () => new Promise((resolve, reject) => {
    const started = performance.now(), socket = net.connect({ host, port });
    const timer = setTimeout(() => { socket.destroy(); reject(new Error('Native refusal baseline timed out')); }, 5000);
    socket.once('connect', () => { clearTimeout(timer); socket.destroy(); reject(new Error('Native closed port was occupied')); });
    socket.once('error', (error) => {
      clearTimeout(timer);
      if (error.code !== 'ECONNREFUSED') reject(error);
      else resolve({ code: error.code, ms: performance.now() - started });
    });
  })));
}

function refusalPackets(stats, refusals) {
  const packets = stats.packetTrace?.records.map((record) => {
    const b = Buffer.from(record.header, 'hex'), offset = (b[0] & 15) * 4;
    if (b[9] !== 6 || b.length < offset + 20) return null;
    return { ...record, source: b.readUInt16BE(offset), target: b.readUInt16BE(offset + 2),
      seq: b.readUInt32BE(offset + 4), ack: b.readUInt32BE(offset + 8), flags: b[offset + 13] };
  }).filter(Boolean);
  assert(packets, 'The OS-limit gate needs the hosted Wintun boundary capture');
  return refusals.map(({ localPort }) => {
    const syn = packets.find((p) => p.direction === 'from-app' && p.source === localPort && p.flags === 2);
    // Retried SYNs reuse the sequence number, and the capture is a ring: the
    // first SYN still in it can be a retry whose original's reset is still
    // there. Match the first reset at or after this SYN (x64 run 39591853359
    // paired a retry with the earlier reset and reported -501 ms).
    const reset = syn && packets.find((p) => p.direction === 'to-app' && p.target === localPort &&
      p.flags === 20 && p.ack === ((syn.seq + 1) >>> 0) && p.at >= syn.at);
    assert(reset && !reset.error && reset.batchWritten === reset.batchPackets,
      `Missing successfully written refusal for app port ${localPort}`);
    const ms = reset.at - syn.at;
    assert(ms >= 0 && ms <= 500, `Engine delayed the reset ${ms} ms for ${localPort}`);
    return { localPort, ms };
  });
}

async function waitForReturnedPorts({ engineStats, before, released, target, nativeExpiryMs, children, evidence, udpHold }) {
  const started = performance.now(), appPorts = new Set(released.localPorts);
  const ownPID = before.nativeSocketState.pid;
  const egressGroups = before.nativeSocketState.groups.filter((g) => g.pid === ownPID && g.state === 5 &&
    g.destination === target.host && target.ports.includes(g.remotePort));
  assert.equal(new Set(egressGroups.map((g) => g.source)).size, 1, 'Capacity egress escaped its one pinned line');
  const egress = new Set(egressGroups.flatMap((g) => g.ports));
  // Each released connection's peer, so a retained watch is matched by the
  // whole connection, not by a local port number Windows may give a new
  // connection to another peer while the old one is in TIME_WAIT.
  const peerOf = (g) => `${g.destination.includes(':') ? `[${g.destination}]` : g.destination}:${g.remotePort}`;
  const egressConnections = new Set(egressGroups.flatMap((g) => g.ports.map((port) => `${port}>${peerOf(g)}`)));
  assert(egress.size >= released.released, 'Native established socket precondition missing');
  const ranges = before.socketResources.configuration.filter((s) => s.DynamicPortRangeNumberOfPorts > 0);
  const closedPorts = new Set();
  assert(ranges.length);
  const { DynamicPortRangeStartPort: start, DynamicPortRangeNumberOfPorts: size } = ranges[0];
  evidence.nativeExpiryMs = nativeExpiryMs;
  evidence.boundMs = Math.max(30_000, nativeExpiryMs + 10_000);
  evidence.observations = [];
  for (;;) {
    const stats = await engineStats(), native = stats.nativeSocketState;
    udpHold.checkStats(stats);
    assert(native && !native.error && !native.handleError, JSON.stringify(native));
    const rows = native.groups.filter((g) => g.destination === target.host && target.ports.includes(g.remotePort));
    const liveEgress = new Set(rows.filter((g) => g.pid === ownPID && g.state === 5).flatMap((g) => g.ports));
    const releasedEgress = new Set([...egress].filter((port) => !liveEgress.has(port)));
    const stateCounts = (ports, source) => {
      const states = {};
      for (const group of rows) {
        if (source && group.source !== source) continue;
        if (!source && group.source === '198.18.0.1') continue;
        for (const port of group.ports) if (ports.has(port)) states[group.state] = (states[group.state] ?? 0) + 1;
      }
      return states;
    };
    const appStates = stateCounts(appPorts, '198.18.0.1'), engineStates = stateCounts(releasedEgress);
    const oldRetainedWatches = stats.nativeReadiness.ports.filter((port) => releasedEgress.has(port)).length;
    const peers = stats.nativeReadiness.peers;
    const retainedWatches = peers ? Object.entries(peers).reduce((sum, [peer, ports]) =>
      sum + ports.filter((port) => releasedEgress.has(port) && egressConnections.has(`${port}>${peer}`)).length, 0)
      : oldRetainedWatches;
    for (const record of stats.nativeReadiness.closes) {
      if (record.sequence > before.nativeReadiness.closedCount && !record.error &&
          record.local.startsWith(`${egressGroups[0].source}:`)) {
        closedPorts.add(Number(record.local.slice(record.local.lastIndexOf(':') + 1)));
      }
    }
    const confirmedCloses = [...releasedEgress].filter((port) => closedPorts.has(port)).length;
    const used = new Set(native.usedLocalPorts.filter((port) => port >= start && port < start + size));
    const elapsedMs = performance.now() - started;
    const observation = { elapsedMs, appStates, engineStates, releasedEgress: releasedEgress.size,
      retainedWatches, oldRetainedWatches, confirmedCloses, handles: native.handles, handlesReleased: before.nativeSocketState.handles - native.handles,
      flows: stats.flows.Flows, tableFreePortUpperBound: size - used.size,
      heapBytes: stats.heapBytes, stackBytes: stats.stackBytes, runtimeBytes: stats.runtimeBytes, gcCPUppm: stats.gcCPUppm };
    evidence.observations.push(observation);
    console.log(`WINDOWS CAPACITY PORT RETURN ${JSON.stringify(observation)}`);
    const clients = await Promise.all(children.map((app) => app.call('status')));
    assert(clients.every((state) => state.held === state.live && state.lost === 0), 'Held flow lost during OS TIME_WAIT');
    assert(clients[0].survival.live && !clients[0].survival.error && clients[0].survival.maxMs <= 1000,
      'Survival stream stalled during OS TIME_WAIT');
    if (elapsedMs >= 2000) {
      assert.equal(releasedEgress.size, released.released, 'Engine left released outbound connections established');
      assert.equal(retainedWatches, 0, 'Engine retained a readiness socket after normal close');
      // Global handles can rise when unrelated apps open new routed flows.
      // Prove successful closes of these exact source sockets, not a static
      // whole-process handle count which would misclassify legitimate work.
      assert.equal(confirmedCloses, released.released, 'Engine did not close every released native descriptor');
    }
    if (releasedEgress.size === released.released && retainedWatches === 0 && confirmedCloses === released.released &&
        Object.keys(appStates).length === 0 && Object.keys(engineStates).length === 0) {
      evidence.returnedAfterMs = elapsedMs;
      evidence.releasedEgress = [...releasedEgress];
      evidence.egressSource = egressGroups[0].source;
      return;
    }
    assert(elapsedMs <= evidence.boundMs, 'Released ports outlived the measured native TIME_WAIT bound');
    await delay(1000); // Observe the OS; do not retry failed connection attempts.
  }
}

export async function capacity({ server, harness, directory, line }) {
  hostedOnly();
  const target = await harness.control('capacity', {});
  const children = [];
  const progress = { oldRuntimeBudgetWouldPass: true, runtimePeakBytes: 0 };
  let udpHold;
  const engineStats = async () => {
    const stats = (await server.api('engine-command', { method: 'stats' })).engine;
    progress.oldRuntimeBudgetWouldPass &&= stats.runtimeBytes <= 512 * 1024 * 1024;
    progress.runtimePeakBytes = Math.max(progress.runtimePeakBytes, stats.runtimeBytes);
    return stats;
  };
  try {
    // Measure this runner's available native pool with routing stopped. No
    // app half, health probe or survival flow competes with the native baseline.
    await server.api('routing', { on: false });
    const refusalBaseline = await nativeRefusalBaseline(harness.uplink.address);
    // Windows retries a refused SYN before ConnectEx reports ECONNREFUSED.
    // Match the existing capped-TCP gate's native-refusal baseline + 500 ms.
    const refusalLimitMs = Math.max(...refusalBaseline.map((sample) => sample.ms)) + 500;
    console.log(`WINDOWS NATIVE REFUSAL BASELINE ${JSON.stringify({ refusalBaseline, refusalLimitMs })}`);
    const nativeOutput = await run(path.resolve('dist/windows-test/windows-platform.test.exe'),
      ['-test.v', '-test.run=^TestNativeBoundPortCapacity$', '-test.timeout=6m'],
      { env: { NETSWITCH_PORT_GATE: '1', NETSWITCH_PORT_BASELINE: 'production' }, timeout: 360_000 });
    const marker = 'WINDOWS NATIVE PORT CAPACITY ';
    const nativeSamples = nativeOutput.stdout.split(/\r?\n/).filter((text) => text.includes(marker))
      .map((text) => JSON.parse(text.slice(text.indexOf(marker) + marker.length)));
    const native = nativeSamples.find((sample) => sample.reuseUnicastPort);
    assert(native && native.connected === native.accepted && native.connected > 0, nativeOutput.stdout);
    const layoutCapacity = Math.floor(native.connected / 2), floor = Math.ceil(layoutCapacity * 0.95);
    const releaseMarker = 'WINDOWS NATIVE PORT RELEASE ';
    const nativeRelease = nativeOutput.stdout.split(/\r?\n/).filter((text) => text.includes(releaseMarker))
      .map((text) => JSON.parse(text.slice(text.indexOf(releaseMarker) + releaseMarker.length)));
    assert(nativeRelease.length && nativeRelease.at(-1).remaining === 0);
    Object.assign(progress, { nativeSamples, nativeRelease, refusalBaseline, refusalLimitMs, floor, layoutCapacity });
    const nativeUDP = await nativeUDPCapacity(harness.testisp);
    await server.api('routing', { on: true });
    await server.on();
    const engineBefore = await server.api('engine-command', { method: 'hello' });
    const portConfiguration = JSON.parse((await run('powershell.exe', ['-NoProfile', '-Command',
      'Get-NetTCPSetting | Select-Object SettingName,DynamicPortRangeStartPort,DynamicPortRangeNumberOfPorts,AutoReusePortRangeStartPort,AutoReusePortRangeNumberOfPorts | ConvertTo-Json -Compress'])).stdout);
    console.log(`WINDOWS PORT CONFIGURATION ${JSON.stringify(portConfiguration)}`);
    // Earlier UDP cases and Windows' adapter-connectivity probes can leave
    // legitimate idle flows. Close that measured setup explicitly through the
    // real protocol; waiting 30 seconds cannot expire a five-minute UDP NAT.
    const preparation = { before: await engineStats(), flows: [], closed: [] };
    let cursor = '';
    do {
      const page = await server.api('engine-command', { method: 'flows', fields: { cursor } });
      preparation.flows.push(...page.flows);
      cursor = page.cursor ?? '';
    } while (cursor);
    for (let at = 0; at < preparation.flows.length; at += 256) {
      const ids = preparation.flows.slice(at, at + 256).map((flow) => flow.id);
      preparation.closed.push(await server.api('engine-command', { method: 'closeFlows',
        fields: { opId: randomUUID(), selector: { ids } } }));
    }
    console.log(`WINDOWS CAPACITY PREPARATION ${JSON.stringify(preparation)}`);
    // None of our test apps' flows may remain. Windows' own background flows
    // (NetBIOS from System, svchost) can reopen at any time (acceptance x64
    // job 119647370936), so they are recorded, never waited for. Ours are the
    // apps started from this checkout, the case's directory, or this Node.
    const ourPrefixes = [path.resolve('.'), directory, process.execPath].map((value) => value.toLowerCase());
    const ours = (flow) => ourPrefixes.some((prefix) => (flow.app?.path ?? '').toLowerCase().startsWith(prefix));
    const listFlows = async () => {
      const flows = [];
      let next = '';
      do {
        const page = await server.api('engine-command', { method: 'flows', fields: { cursor: next } });
        flows.push(...page.flows);
        next = page.cursor ?? '';
      } while (next);
      return flows;
    };
    const before = await until(async () => {
      const flows = await listFlows();
      if (flows.some(ours)) return false;
      const stats = await engineStats();
      preparation.foreignFlows = flows.map((flow) => ({ protocol: flow.protocol, destination: flow.destination, app: flow.app?.path }));
      return stats;
    }, 'no flows of our test apps before capacity measurement', 30_000);
    console.log(`WINDOWS CAPACITY FOREIGN FLOWS ${JSON.stringify(preparation.foreignFlows)}`);
    // The controller needs a port too. Establish one durable connection before
    // pressure; fetch's four-second idle eviction otherwise makes inspection
    // itself fail with ENOBUFS. No automatic reconnect is allowed.
    const controlReservation = await harness.reserveControl();
    progress.baselineHeap = await captureHeap(server, 'mixed-baseline', 0, 0);
    progress.largeUDP = await largeUDPReplies({ server, harness, directory, line });
    progress.udp = {};
    udpHold = await holdUDPCapacity({ server, harness, directory, line, native: nativeUDP, evidence: progress.udp });
    // Evidence only: the UDP recovery cycles matched to the native control
    // (UDP at the limit, no TCP load yet), so only the engine differs.
    progress.udp.matchedCycles = await udpHold.evidenceCycles(udpRecoveryCycles);
    udpHold.checkStats(await engineStats());
    for (let i = 0; i < 8; i++) {
      const exe = path.join(directory, `capacity-app-${i}.exe`);
      await copyFile(process.execPath, exe);
      await server.api('app-line', { path: exe, line });
      const child = spawn(exe, [path.resolve('tests/windows/capacity-client.mjs')], { windowsHide: true, stdio: ['ignore','inherit','inherit','ipc'] });
      let serial = 0;
      const pending = new Map();
      child.on('message', ({ id, result, error }) => {
        const item = pending.get(id);
        if (!item) return;
        pending.delete(id); clearTimeout(item.timer);
        if (error) item.reject(new Error(error)); else item.resolve(result);
      });
      child.on('exit', () => {
        for (const item of pending.values()) { clearTimeout(item.timer); item.reject(new Error('Capacity client exited')); }
        pending.clear();
      });
      const call = (command, args = {}) => new Promise((resolve, reject) => {
        const id = ++serial;
        const timer = setTimeout(() => { pending.delete(id); reject(new Error(`Capacity client ${i}: ${command} deadline`)); }, 60_000);
        pending.set(id, { resolve, reject, timer });
        child.send({ id, command, ...args });
      });
      children.push({ child, call, exe });
    }
    const probeBaseline = await children[0].call('probe', target);
    assert.equal(probeBaseline.code, 'OK', `Fixed-source-port probe precondition failed: ${JSON.stringify(probeBaseline)}`);
    const oldEchoBasedLimitMs = probeBaseline.ms + 500;
    await children[0].call('survival', target);
    // Wrong-line admissions: a TCP SYN whose owner lookup failed is admitted as
    // an unknown app and sent to the default line instead of its pinned one
    // (x64 run 39602903586). Count them over the fill and the refusal tail.
    const admissionsBefore = await engineStats();
    const unknownTCP = (stats) => stats.flows.AdmittedUnknown - stats.flows.AdmittedUnknownUDP;
    let held = 1, firstLimit;
    // Both halves allocate from the same unchanged Windows ephemeral pool.
    // Internal engine ceilings remain 65,536 total / 8,192 per app.
    while (held < 65536 && !firstLimit) {
      for (const app of children) {
        const result = await app.call('open', { ...target, count: 256, timeout: refusalLimitMs });
        assert.equal(result.lost, 0, 'A previously admitted capacity socket was cut');
        held += result.opened;
        assert(result.held <= 8192);
        if (result.failures.length) { firstLimit = result.failures; break; }
      }
      const stats = await engineStats();
      udpHold.checkStats(stats);
      console.log(`WINDOWS CAPACITY ${JSON.stringify({ held, flows: stats.flows.Flows, heapBytes: stats.heapBytes, stackBytes: stats.stackBytes, runtimeBytes: stats.runtimeBytes, gcCPUppm: stats.gcCPUppm })}`);
    }
    assert(firstLimit?.length, 'Expected the runner OS limit before the internal ceiling');
    assert(firstLimit.every((failure) => ['ENOBUFS', 'EADDRINUSE', 'ECONNREFUSED', 'ECONNRESET'].includes(failure.code)),
      `The limit was a stall or unrelated failure: ${JSON.stringify(firstLimit)}`);
    assert(held >= floor, `Held ${held}, below 95% of this runner's isolated two-half layout ${layoutCapacity}: ${JSON.stringify(nativeSamples)}`);
    const ordinaryHeld = held;
    progress.ordinaryHeld = ordinaryHeld;
    const limitStats = await engineStats();
    const refusals = [], extraAdmissions = [], resetTimings = [];
    // Failed ordinary connects release their app-side ports; unrelated OS
    // sockets can also close. Keep each subsequently successful fixed-port
    // probe, recording it, until the engine itself refuses native allocation.
    // This is bounded and reports every attempt; the 95% floor already passed
    // with ordinary two-half flows before this tail of one-half probes.
    for (let n = 0; n < 512 && refusals.length < 128;) {
      const batch = await Promise.all(Array.from({ length: Math.min(32, 128 - refusals.length, 512 - n) },
        () => children[0].call('probe', { ...target, localPort: 45001 + n++, keep: true, timeout: refusalLimitMs })));
      const rejected = [];
      for (const refusal of batch) {
        if (refusal.code === 'OK') { extraAdmissions.push(refusal); held++; continue; }
        refusals.push(refusal); rejected.push(refusal);
        assert(['ECONNREFUSED', 'ECONNRESET'].includes(refusal.code) && refusal.ms <= refusalLimitMs,
          `OS-limit flow was not reset promptly: ${JSON.stringify({ refusal, refusalLimitMs })}`);
      }
      resetTimings.push(...refusalPackets(await engineStats(), rejected));
    }
    assert.equal(refusals.length, 128, 'Did not establish the actual native allocation limit');
    Object.assign(progress, { held, firstLimit, refusals, resetTimings, extraAdmissions });
    const refusedStats = await engineStats();
    const lookup = (stats) => stats.ownerLookup ?? {};
    progress.wrongLine = { unknownTCPAdmissions: unknownTCP(refusedStats) - unknownTCP(admissionsBefore),
      lookups: lookup(refusedStats).count - (lookup(admissionsBefore).count ?? 0),
      misses: lookup(refusedStats).misses - (lookup(admissionsBefore).misses ?? 0),
      holds: lookup(refusedStats).tcpHolds, heldFound: lookup(refusedStats).tcpHeldFound,
      lateIdentities: lookup(refusedStats).tcpLateIdentities, maxUS: lookup(refusedStats).maxUS,
      tcpReadMaxUS: lookup(refusedStats).tcpReadMaxUS, tcpReadBuckets: lookup(refusedStats).tcpReadBuckets,
      upperUS: lookup(refusedStats).upperUS, peakRows: lookup(refusedStats).tcpPeakRows, failures: lookup(refusedStats).failures };
    console.log(`WINDOWS CAPACITY WRONG-LINE ${JSON.stringify(progress.wrongLine)}`);
    assert.equal(progress.wrongLine.unknownTCPAdmissions, 0, 'A capacity SYN lost its owner and left on the default line');
    assert(refusedStats.socketResources.exhaustions >= 128, 'Native bind failures were not counted');
    assert(refusedStats.tcpDialFailed - limitStats.tcpDialFailed >= 128, 'Refused app flows were not counted by the engine');
    const health = await server.api('engine-command', { method: 'probe', fields: {
      opId: randomUUID(), line, operator: `${target.host}:${target.ports[0]}` } });
    assert.equal(health.outcome, 'engineUnavailable', 'Local port exhaustion was treated as line failure');
    const portStats = await until(async () => {
      const stats = await engineStats();
      udpHold.checkStats(stats);
      assert.notEqual(stats.socketResources.configurationStatus, 'error', JSON.stringify(stats.socketResources));
      return stats.socketResources.configurationStatus === 'ready' && stats.socketResources;
    }, 'OS port configuration visible in engine stats', 65_000);
    assert(portStats.configuration.some((setting) => setting.DynamicPortRangeNumberOfPorts > 0));
    const observed = await harness.control('capacity');
    assert(observed.echoed >= held, 'The controlled peer did not echo every admitted flow');
    const verifiedBefore = await Promise.all(children.map((app) => app.call('verify')));
    assert(verifiedBefore.reduce((n, state) => n + state.checked, 1) === held);
    const samples = [];
    for (let n = 0; n < 10; n++) {
      const states = await Promise.all(children.map((app) => app.call('status')));
      assert(states.every((s) => s.held === s.live && s.lost === 0), JSON.stringify(states));
      assert.equal(states.reduce((total, s) => total + s.live, 1), held);
      const survival = states[0].survival;
      assert(survival.live && !survival.error && survival.received >= survival.sent - 1 && survival.maxMs <= 1000,
        `Survival stream stalled: ${JSON.stringify(survival)}`);
      const stats = await engineStats();
      udpHold.checkStats(stats);
      assert(stats.flows.Flows >= held, 'The engine lost a held flow');
      assert.equal(stats.flows.Handshakes, 0);
      assert(stats.processMemory?.privateBytes > 0 && stats.processMemory?.workingSetBytes > 0,
        `Windows process memory was not measured: ${JSON.stringify(stats)}`);
      samples.push(stats);
      await delay(1000);
    }
    progress.udp.mixedVerified = await udpHold.verify();
    progress.heldHeap = await captureHeap(server, 'mixed-held', held, udpHold.held, progress.baselineHeap);
    const afterGC = await Promise.all(children.map((app) => app.call('verify')));
    assert.equal(afterGC.reduce((n, state) => n + state.checked, 1), held,
      'A TCP holder disappeared during forced GC');
    progress.udp.afterMixedGC = await udpHold.verify();
    const beforeRelease = await engineStats();
    const released = await children[0].call('release', { count: 512 });
    assert.equal(released.released, 512);
    const portReturn = progress.portReturn = { released, beforeHandles: beforeRelease.nativeSocketState.handles };
    await waitForReturnedPorts({ engineStats, before: beforeRelease, released, target,
      nativeExpiryMs: nativeRelease.at(-1).elapsedMS, children, evidence: portReturn, udpHold });
    const returnedPortProbe = await run(path.resolve('dist/windows-test/windows-platform.test.exe'),
      ['-test.v', '-test.run=^TestReturnedPortsBindWithoutReuse$', '-test.timeout=30s'],
      { env: { NETSWITCH_RETURNED_PORTS: JSON.stringify([
        { source: '198.18.0.1', ports: released.localPorts },
        { source: portReturn.egressSource, ports: portReturn.releasedEgress },
      ]) }, timeout: 30_000 });
    portReturn.nativeBindEvidence = returnedPortProbe.stdout;
    // SYSTEM-DESIGN 5.9 amended: every one of the 256 is attempted; each
    // refused first attempt gets one explicit re-attempt, and with any
    // refusal the whole reopen takes at most the recovery window. The bind
    // probe above is the no-leak check (it fails on any unbindable port).
    const portsBefore = (await engineStats()).socketResources?.exhaustions ?? 0;
    const recoveryStarted = performance.now();
    const recovered = await children[0].call('open', { ...target, count: 256, timeout: refusalLimitMs, all: true });
    const reattempt = recovered.failures.length
      ? await children[0].call('open', { ...target, count: recovered.failures.length, timeout: refusalLimitMs, all: true })
      : null;
    const recoveryMs = performance.now() - recoveryStarted;
    const tcpEngineRefusals = ((await engineStats()).socketResources?.exhaustions ?? 0) - portsBefore;
    const tcpRecovery = portRecoveryGate({ requested: 256,
      firstFailures: recovered.failures.map((item) => ({ call: item.call, code: item.code })),
      reattempted: reattempt ? recovered.failures.length : 0, reattemptFailures: reattempt?.failures ?? [], elapsedMS: recoveryMs,
      leak: { ok: true }, // run() above rejects when the bind probe fails
      engineBinds: { firstRefusals: tcpEngineRefusals, finalFailures: tcpEngineRefusals } });
    Object.assign(progress, { recovered, reattempt, recoveryMs, tcpRecovery });
    console.log(`WINDOWS TCP RECOVERY VERDICT ${JSON.stringify(tcpRecovery)}`);
    assert.equal(tcpRecovery.newVerdict, 'pass', `Capacity did not return after ports were freed: ${JSON.stringify({ tcpRecovery, recovered, reattempt })}`);
    await udpHold.recover();
    const verifiedAfter = await Promise.all(children.map((app) => app.call('verify')));
    assert(verifiedAfter.every((s) => s.held === s.live && s.lost === 0), JSON.stringify(verifiedAfter));
    assert.equal(verifiedAfter.reduce((total, s) => total + s.live, 1), held - 512 + 256);
    progress.recoveryHeap = await captureHeap(server, 'after-recovery', held - 512 + 256, udpHold.held, progress.baselineHeap);
    const engineAfter = await server.api('engine-command', { method: 'hello' });
    assert.equal(engineAfter.engineInstanceId, engineBefore.engineInstanceId, 'The engine restarted under port pressure');
    const last = samples.at(-1);
    const evidence = { nativeSamples, layoutCapacity, floor, ordinaryHeld, held, firstLimit, extraAdmissions, refusals,
      udp: progress.udp, largeUDP: progress.largeUDP,
      baselineHeap: progress.baselineHeap, heldHeap: progress.heldHeap, recoveryHeap: progress.recoveryHeap,
      oldRuntimeBudgetWouldPass: progress.oldRuntimeBudgetWouldPass && progress.udp.oldRuntimeBudgetWouldPass,
      runtimePeakBytes: Math.max(progress.runtimePeakBytes, progress.udp.runtimePeakBytes),
      nativeRelease, refusalBaseline, refusalLimitMs, resetTimings, oldEchoBasedLimitMs, controlReservation, portReturn,
      oldImmediateRecoveryCheckWouldPass: portReturn.returnedAfterMs + recoveryMs <= refusalLimitMs,
      oldOneSecondCheckWouldPass: [...firstLimit, ...refusals].every((failure) => failure.ms <= 1000),
      oldEchoBasedCheckWouldPass: refusals.every((failure) => failure.ms <= oldEchoBasedLimitMs), portStats,
      portConfiguration, preparation, before, samples, observed, verifiedBefore, verifiedAfter, released, recovered, recoveryMs,
      old65536CheckWouldPass: held === 65536, internalTotalCeiling: 65536, internalPerAppCeiling: 8192,
      mixedHeld: held + progress.udp.held,
      heapPerFlow: progress.heldHeap.perFlow.heapBytes, stackPerFlow: progress.heldHeap.perFlow.stackBytes,
      oldUncollectedHeapPerFlow: last.heapBytes / (held + progress.udp.held),
      oldUncollectedStackPerFlow: last.stackBytes / (held + progress.udp.held),
      privatePerFlow: last.processMemory.privateBytes / (held + progress.udp.held),
      workingSetPerFlow: last.processMemory.workingSetBytes / (held + progress.udp.held),
      gcCPUppm: last.gcCPUppm,
      capWindowGCShare: (last.gcCPUNanos - samples[0].gcCPUNanos) / Math.max(1, last.totalCPUNanos - samples[0].totalCPUNanos) };
    console.log(`WINDOWS OS-LIMIT CAPACITY RESULT ${JSON.stringify(evidence)}`);
    return evidence;
  } catch (error) {
    // Read this before closing fixture sockets: teardown would erase the
    // held-flow state and overwrite a bounded SYN/RST boundary capture.
    error.evidence = {
      progress,
      statsBeforeCleanup: await engineStats().catch((failure) => ({ error: failure.message })),
      clientsBeforeCleanup: await Promise.all(children.map(({ call }) => call('status').catch((failure) => ({ error: failure.message })))),
    };
    throw error;
  } finally {
    let udpCloseError;
    if (udpHold) await udpHold.close().catch((error) => { udpCloseError = error; });
    for (const { child, call } of children) {
      if (child.connected) { await call('close').catch(() => {}); child.disconnect(); }
    }
    // Health probes through TestISP used its reserved upstream ports, not the
    // PC's exhausted pool (a real router's own port space); say so.
    const closed = await harness.control('capacity-close', {});
    console.log(`WINDOWS TESTISP PROBE RELAY ${JSON.stringify(closed.probeRelay ?? { mode: 'not active' })}`);
    if (udpCloseError) throw udpCloseError;
  }
}
