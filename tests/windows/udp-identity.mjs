import assert from 'node:assert/strict';
import { copyFile } from 'node:fs/promises';
import { randomBytes } from 'node:crypto';
import path from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import { run } from './testisp/harness.mjs';

export async function udpIdentity({ server, responder, directory, main, second, blocked }) {
  const firstExe = path.join(directory, 'identity-first.exe');
  const nextExe = path.join(directory, 'identity-next.exe');
  await copyFile(path.resolve('dist/windows-test/udpreject.exe'), firstExe);
  await copyFile(path.resolve('dist/windows-test/udpreject.exe'), nextExe);
  const tokenA = randomBytes(16).toString('hex'), tokenB = randomBytes(16).toString('hex');
  const port = blocked ? 40124 : 40123;
  const invoke = async (exe, token, duration) => JSON.parse((await run(exe, [
    '--address', `${responder.virtual.host}:${responder.virtual.udp[0]}`, '--stream',
    '--local-port', String(port), '--duration', duration, '--token', token,
  ], { timeout: 15_000 })).stdout);
  await server.api('app-line', { path: firstExe, line: second.id });
  await server.api('app-line', { path: nextExe, line: main.id });
  try {
    if (blocked) {
      // Establish the second app's block before the first socket exists; a
      // closeFlows call must not accidentally perform identity invalidation.
      await server.api('lines/order', { ids: [second.id, main.id] });
      await server.api('lines/update', { id: second.id, strict: true });
      await server.api('lines/update', { id: main.id, cap: { bytes: 1, period: 'day' } });
      const state = await server.api('state');
      assert(state.lines.find((l) => l.id === main.id).blocked, 'Blocked reuse needs an already-blocked destination lane');
    }
    const first = await invoke(firstExe, tokenA, '2s');
    const firstObserved = responder.seen.filter((r) => r.token === tokenA);
    assert(firstObserved.length >= 50 && first.events.filter((e) => e.outcome === 'reply').length >= 50, 'The old socket did not establish a real NAT mapping');
    const nextResult = invoke(nextExe, tokenB, '3s');
    await delay(1250);
    const flows = await server.api('engine-command', { method: 'flows' });
    const next = await nextResult;
    assert.equal(next.source, first.source, 'Reuse changed the source tuple');
    assert(next.sent >= 100);
    const late = responder.seen.filter((r) => r.token === tokenB && r.at >= next.startedAt + 1000);
    assert.equal(late.length, 0, `The replacement socket kept using the first app's TestISP mapping: ${JSON.stringify(late)}`);
    if (blocked) {
      assert(next.events.some((e) => e.at >= next.startedAt + 1000 && e.outcome === 'refused'), 'Blocked replacement never received an ICMP refusal');
    } else {
      const row = flows.flows.find((f) => f.protocol === 'udp' && f.app.path.toLowerCase() === nextExe.toLowerCase() && f.source.endsWith(`:${port}`));
      assert(row && row.line === main.id && main.addresses.includes(row.physicalSource), `Replacement was not source-bound to its own line: ${JSON.stringify(row)}`);
      // The controlled virtual destination exists only on TestISP. A main-line
      // send cannot reach it; packet absence alone is therefore insufficient.
      assert(row.up > 0 && row.app.socketGeneration, 'The replacement needs an active, attributed native socket');
    }
    return { first, next, firstObserved, late, flows: flows.flows, virtualDestinationOnlyOnTestISP: true };
  } finally {
    if (blocked) {
      await server.api('lines/update', { id: main.id, cap: null });
      await server.api('lines/update', { id: second.id, strict: false });
      await server.api('lines/order', { ids: [main.id, second.id] });
    }
  }
}
