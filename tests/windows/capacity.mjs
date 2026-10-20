import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import { copyFile } from 'node:fs/promises';
import path from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import { hostedOnly, run, until } from './testisp/harness.mjs';

export async function capacity({ server, harness, directory, line }) {
  hostedOnly();
  const target = await harness.control('capacity', {});
  const children = [];
  const engineStats = async () => (await server.api('engine-command', { method: 'stats' })).engine;
  try {
    // Measure this runner's available native pool with routing stopped. No
    // app half, health probe or survival flow competes with the native baseline.
    await server.api('routing', { on: false });
    const nativeOutput = await run(path.resolve('dist/windows-test/windows-platform.test.exe'),
      ['-test.v', '-test.run=^TestNativeBoundPortCapacity$', '-test.timeout=5m'],
      { env: { NETSWITCH_PORT_GATE: '1' }, timeout: 300_000 });
    const marker = 'WINDOWS NATIVE PORT CAPACITY ';
    const nativeSamples = nativeOutput.stdout.split(/\r?\n/).filter((text) => text.includes(marker))
      .map((text) => JSON.parse(text.slice(text.indexOf(marker) + marker.length)));
    const native = nativeSamples.find((sample) => sample.reuseUnicastPort);
    assert(native && native.connected === native.accepted && native.connected > 0, nativeOutput.stdout);
    const layoutCapacity = Math.floor(native.connected / 2), floor = Math.ceil(layoutCapacity * 0.95);
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
    const before = await until(async () => {
      const stats = await engineStats();
      return stats.flows.Flows === 0 && stats;
    }, 'no ordinary flows before capacity measurement', 30_000);
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
    const refusalLimitMs = probeBaseline.ms + 500; // Same allowance as the existing capped-TCP refusal gate.
    await children[0].call('survival', target);
    let held = 1, firstLimit;
    // Both halves allocate from the same unchanged Windows ephemeral pool.
    // Internal engine ceilings remain 65,536 total / 8,192 per app.
    while (held < 65536 && !firstLimit) {
      for (const app of children) {
        const result = await app.call('open', { ...target, count: 256 });
        assert.equal(result.lost, 0, 'A previously admitted capacity socket was cut');
        held += result.opened;
        assert(result.held <= 8192);
        if (result.failures.length) { firstLimit = result.failures; break; }
      }
      const stats = await engineStats();
      console.log(`WINDOWS CAPACITY ${JSON.stringify({ held, flows: stats.flows.Flows, heapBytes: stats.heapBytes, stackBytes: stats.stackBytes, runtimeBytes: stats.runtimeBytes, gcCPUppm: stats.gcCPUppm })}`);
      assert(stats.runtimeBytes <= 512 * 1024 * 1024, 'Runtime budget exceeded during admission');
    }
    assert(firstLimit?.length, 'Expected the runner OS limit before the internal ceiling');
    assert(firstLimit.every((failure) => ['ENOBUFS', 'EADDRINUSE', 'ECONNREFUSED', 'ECONNRESET'].includes(failure.code)),
      `The limit was a stall or unrelated failure: ${JSON.stringify(firstLimit)}`);
    assert(held >= floor, `Held ${held}, below 95% of this runner's isolated two-half layout ${layoutCapacity}: ${JSON.stringify(nativeSamples)}`);
    const ordinaryHeld = held;
    const limitStats = await engineStats();
    const refusals = [], extraAdmissions = [];
    // Failed ordinary connects release their app-side ports; unrelated OS
    // sockets can also close. Keep each subsequently successful fixed-port
    // probe, recording it, until the engine itself refuses native allocation.
    // This is bounded and reports every attempt; the 95% floor already passed
    // with ordinary two-half flows before this tail of one-half probes.
    for (let n = 0; n < 512 && refusals.length < 128; n++) {
      const refusal = await children[0].call('probe', { ...target, localPort: 45001 + n, keep: true });
      if (refusal.code === 'OK') { extraAdmissions.push(refusal); held++; continue; }
      refusals.push(refusal);
      assert(['ECONNREFUSED', 'ECONNRESET'].includes(refusal.code) && refusal.ms <= refusalLimitMs,
        `OS-limit flow was not reset promptly: ${JSON.stringify({ refusal, refusalLimitMs })}`);
    }
    assert.equal(refusals.length, 128, 'Did not establish the actual native allocation limit');
    const refusedStats = await engineStats();
    assert(refusedStats.socketResources.exhaustions >= 128, 'Native bind failures were not counted');
    assert(refusedStats.tcpDialFailed - limitStats.tcpDialFailed >= 128, 'Refused app flows were not counted by the engine');
    const health = await server.api('engine-command', { method: 'probe', fields: {
      opId: randomUUID(), line, operator: `${target.host}:${target.ports[0]}` } });
    assert.equal(health.outcome, 'engineUnavailable', 'Local port exhaustion was treated as line failure');
    const portStats = await until(async () => {
      const stats = await engineStats();
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
      assert(stats.flows.Flows >= held, 'The engine lost a held flow');
      assert.equal(stats.flows.Handshakes, 0);
      assert(stats.processMemory?.privateBytes > 0 && stats.processMemory?.workingSetBytes > 0,
        `Windows process memory was not measured: ${JSON.stringify(stats)}`);
      samples.push(stats);
      await delay(1000);
    }
    const released = await children[0].call('release', { count: 512 });
    assert.equal(released.released, 512);
    const recoveryStarted = performance.now();
    const recovered = await children[0].call('open', { ...target, count: 256 });
    const recoveryMs = performance.now() - recoveryStarted;
    assert.equal(recovered.opened, 256, 'Capacity did not return after ports were freed');
    assert.equal(recovered.failures.length, 0, JSON.stringify(recovered.failures));
    const verifiedAfter = await Promise.all(children.map((app) => app.call('verify')));
    assert(verifiedAfter.every((s) => s.held === s.live && s.lost === 0), JSON.stringify(verifiedAfter));
    assert.equal(verifiedAfter.reduce((total, s) => total + s.live, 1), held - 512 + 256);
    const engineAfter = await server.api('engine-command', { method: 'hello' });
    assert.equal(engineAfter.engineInstanceId, engineBefore.engineInstanceId, 'The engine restarted under port pressure');
    const last = samples.at(-1);
    const evidence = { nativeSamples, layoutCapacity, floor, ordinaryHeld, held, firstLimit, extraAdmissions, refusals, refusalLimitMs, portStats,
      portConfiguration, preparation, before, samples, observed, verifiedBefore, verifiedAfter, released, recovered, recoveryMs,
      old65536CheckWouldPass: held === 65536, internalTotalCeiling: 65536, internalPerAppCeiling: 8192,
      heapPerFlow: last.heapBytes / held, stackPerFlow: last.stackBytes / held,
      privatePerFlow: last.processMemory.privateBytes / held,
      workingSetPerFlow: last.processMemory.workingSetBytes / held,
      gcCPUppm: last.gcCPUppm,
      capWindowGCShare: (last.gcCPUNanos - samples[0].gcCPUNanos) / Math.max(1, last.totalCPUNanos - samples[0].totalCPUNanos) };
    console.log(`WINDOWS OS-LIMIT CAPACITY RESULT ${JSON.stringify(evidence)}`);
    assert(samples.every((s) => s.runtimeBytes <= 512 * 1024 * 1024), `512 MiB runtime budget exceeded: ${JSON.stringify(evidence)}`);
    return evidence;
  } finally {
    for (const { child, call } of children) {
      if (child.connected) { await call('close').catch(() => {}); child.disconnect(); }
    }
    await harness.control('capacity-close', {});
  }
}
