import assert from 'node:assert/strict';
import { writeFile } from 'node:fs/promises';
import { startHarness, hostedOnly, until } from './harness.mjs';
import { localTraffic, proveDefaultRoute } from '../local-traffic.mjs';

hostedOnly();
const dir = 'dist/testisp-proof';
const results = [];
let harness, responder;
async function check(name, fn) {
  const start = Date.now();
  try { const evidence = await fn(); results.push({ name, status: 'pass', ms: Date.now() - start, evidence }); console.log(`PASS ${name}: ${JSON.stringify(evidence)}`); }
  catch (error) { results.push({ name, status: 'fail', ms: Date.now() - start, error: error.stack }); throw error; }
}
try {
  harness = await startHarness(dir);
  const { uplink, testisp, probe, control, network } = harness;
  responder = await localTraffic(harness, dir);
  await check('direct uplink baseline', async () => {
    const before = await control('stats');
    const response = await probe(uplink);
    const after = await control('stats');
    assert.equal(after.testisp.connections, before.testisp.connections, 'Direct traffic entered TestISP');
    return { response, before, after };
  });
  await check('TestISP egress and reverse relay', async () => {
    const before = await control('stats');
    const response = await probe(testisp);
    const after = await until(async () => {
      const stats = await control('stats');
      return stats.uplink.bytesIn > before.uplink.bytesIn && stats.uplink.bytesOut > before.uplink.bytesOut && stats;
    }, 'upstream relay byte counts');
    assert(after.testisp.connections > before.testisp.connections);
    assert(after.testisp.bytesIn > before.testisp.bytesIn && after.testisp.bytesOut > before.testisp.bytesOut);
    assert(after.destinations['1.1.1.1:443'] > 0);
    return { response, before, after };
  });
  await check('local TLS requires the TestISP default route', () => proveDefaultRoute(harness, responder));
  for (const mode of ['pause', 'drop']) {
    await check(`${mode} TestISP leaves direct uplink working`, async () => {
      await control('mode', { mode });
      const failed = await probe(testisp, true, responder);
      const direct = await probe(uplink);
      await control('mode', { mode: 'running' });
      const recovered = await probe(testisp, false, responder);
      return { failed, direct, recovered, stats: await control('stats') };
    });
  }
  await check('withdraw TestISP default route', async () => {
    await network('withdraw');
    const failed = await probe(testisp, 'unreachable', responder);
    const direct = await probe(uplink);
    await network('restore');
    return { failed, direct, recovered: await probe(testisp, false, responder) };
  });
  await check('block direct probe leaves TestISP working', async () => {
    await network('block-direct');
    const failed = await probe(uplink, true);
    const virtual = await probe(testisp);
    await network('unblock-direct');
    return { failed, virtual, recovered: await probe(uplink) };
  });
  await check('normal adapter, route, firewall and PnP cleanup', () => harness.close());
  harness = null;
  harness = await startHarness(`${dir}/crash`);
  await check('forced gateway death leaves an orphan that our recovery removes', () => harness.close({ crash: true }));
  harness = null;
} catch (error) { console.error(error); process.exitCode = 1; }
finally {
  if (harness) {
    try { await check('adapter, route and firewall cleanup', () => harness.close()); }
    catch (error) { console.error(error); process.exitCode = 1; }
  }
  if (responder) {
    await writeFile(`${dir}/tls-observations.json`, JSON.stringify(responder.seen, null, 2));
    await responder.close();
  }
  await writeFile(`${dir}/report.json`, JSON.stringify({ architecture: process.arch, results }, null, 2));
}
