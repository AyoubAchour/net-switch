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
    // One batch at a time across the eight app identities. Each process has
    // its own executable path; no injected owner bypasses the per-app cap.
    for (let held = 0; held < 65536;) {
      for (const app of children) {
        const result = await app.call('open', { ...target, count: 256 });
        assert.equal(result.lost, 0, 'A previously admitted capacity socket was cut');
        held += 256;
      }
      const stats = await engineStats();
      console.log(`WINDOWS CAPACITY ${JSON.stringify({ held, flows: stats.flows.Flows, heapBytes: stats.heapBytes, stackBytes: stats.stackBytes, runtimeBytes: stats.runtimeBytes, gcCPUppm: stats.gcCPUppm })}`);
    }
    const observed = await harness.control('capacity');
    assert.equal(observed.echoed, 65536, 'The controlled peer did not echo every admitted flow');
    const samples = [];
    for (let n = 0; n < 10; n++) {
      const states = await Promise.all(children.map((app) => app.call('status')));
      assert(states.every((s) => s.held === 8192 && s.live === 8192 && s.lost === 0), JSON.stringify(states));
      const stats = await engineStats();
      assert.equal(stats.flows.Flows, 65536, 'The engine did not retain the actual flow cap');
      assert.equal(stats.flows.Handshakes, 0);
      assert(stats.processMemory?.privateBytes > 0 && stats.processMemory?.workingSetBytes > 0,
        `Windows process memory was not measured: ${JSON.stringify(stats)}`);
      samples.push(stats);
      await delay(1000);
    }
    const last = samples.at(-1);
    const evidence = { portConfiguration, preparation, before, samples, observed,
      heapPerFlow: last.heapBytes / 65536, stackPerFlow: last.stackBytes / 65536,
      privatePerFlow: last.processMemory.privateBytes / 65536,
      workingSetPerFlow: last.processMemory.workingSetBytes / 65536,
      gcCPUppm: last.gcCPUppm,
      capWindowGCShare: (last.gcCPUNanos - samples[0].gcCPUNanos) / Math.max(1, last.totalCPUNanos - samples[0].totalCPUNanos) };
    console.log(`WINDOWS CAPACITY RESULT ${JSON.stringify(evidence)}`);
    assert(samples.every((s) => s.runtimeBytes <= 512 * 1024 * 1024), `512 MiB runtime budget exceeded: ${JSON.stringify(evidence)}`);
    return evidence;
  } finally {
    for (const { child, call } of children) {
      if (child.connected) { await call('close').catch(() => {}); child.disconnect(); }
    }
    await harness.control('capacity-close', {});
  }
}
