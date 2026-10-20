import assert from 'node:assert/strict';
import { writeFile } from 'node:fs/promises';
import path from 'node:path';
import { localHttps } from '../../scripts/tun-test-https.mjs';

export async function localTraffic(harness, directory) {
  const responder = await localHttps(harness.uplink.address);
  try {
    responder.caFile = path.join(directory, 'local-traffic-ca.pem');
    await writeFile(responder.caFile, responder.target.ca);
    responder.destination = `${responder.address}:${responder.port}`;
    responder.target = { ...responder.target, tls: true };
    return responder;
  } catch (error) { await responder.close(); throw error; }
}

// Use exactly the same endpoint as the engine rewrite, with both source and
// IP_UNICAST_IF bound by the native probe. No route to the target is installed.
export async function proveDefaultRoute(harness, responder) {
  const before = await harness.control('stats');
  const working = await harness.probe(harness.testisp, false, responder);
  const after = await harness.control('stats');
  assert.equal((after.destinations[responder.destination] ?? 0) - (before.destinations[responder.destination] ?? 0), 1);
  try {
    await harness.network('withdraw');
    assert.equal((await harness.network('state')).defaultRoute, false);
    const seen = responder.seen.length;
    const failed = await harness.probe(harness.testisp, true, responder);
    assert.equal(responder.seen.length, seen, 'Withdrawn line still reached the responder');
    const withdrawn = await harness.control('stats');
    assert.equal(withdrawn.destinations[responder.destination], after.destinations[responder.destination], 'Withdrawn line still reached TestISP');
    await harness.network('restore');
    const recovered = await harness.probe(harness.testisp, false, responder);
    const restored = await harness.control('stats');
    assert.equal(restored.destinations[responder.destination] - after.destinations[responder.destination], 1);
    const evidence = { destination: responder.destination, working, failed, recovered, before, after, withdrawn, restored };
    console.log(`DEFAULT-ROUTE PROOF ${JSON.stringify(evidence)}`);
    return evidence;
  } finally { await harness.network('restore'); }
}
