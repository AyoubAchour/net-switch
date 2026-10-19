// A controlled UDP peer for the Windows TUN suite. The ordinary engine tests
// keep the product config unchanged; only this separate fixture redirects a
// reserved test address to a responder on the runner's physical interface.
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { createSocket } from 'node:dgram';
import { once } from 'node:events';
import { mkdir, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import { Engine, buildEngineConfig, freePort } from '../lib/engine.mjs';
import { lineOutbound } from '../lib/apps.mjs';

export async function testLocalUdp({ client, clientExe, adapter, dataDir, log }) {
  if (process.platform !== 'win32' || process.env.GITHUB_ACTIONS !== 'true' || process.env.RUNNER_ENVIRONMENT !== 'github-hosted') {
    throw new Error('The UDP TUN fixture is restricted to disposable Windows CI runners.');
  }
  assert(adapter.ipv4, 'The UDP fixture needs the physical adapter IPv4 address');
  const destination = '203.0.113.53';
  const dir = path.join(dataDir, 'udp');
  await mkdir(dir, { recursive: true });
  const responder = createSocket('udp4');
  const received = [];
  let responderError, child;
  let output = '';
  responder.on('error', (error) => { responderError = error; });
  responder.on('message', (query, peer) => {
    received.push({ bytes: query.length, peer: peer.address });
    if (query.length < 12) return;
    // Keep the question and EDNS padding, so both directions carry the full
    // packet. No recursive lookup or upstream DNS service is involved.
    const reply = Buffer.from(query);
    reply.writeUInt16BE(0x8183, 2);
    responder.send(reply, peer.port, peer.address, (error) => { if (error) responderError = error; });
  });
  try {
    responder.bind(0, adapter.ipv4);
    await once(responder, 'listening');
    const port = responder.address().port;
    for (const size of [64, 1800]) {
      const result = await client('udp', { size, server: adapter.ipv4, port });
      assert.equal(result.received, size, 'Direct UDP reply changed size');
      log(`UDP direct baseline: ${JSON.stringify(result)}`);
    }

    // Reuse the real config builder, checksums, rule sets and Clash API. The
    // sole added rule is non-final: normal process pins and selectors still
    // choose the outbound. This fixture does not use or alter engine.pid.
    const engine = new Engine({ singBoxPath: path.resolve('engine/sing-box.exe'), dataDir: dir, mode: 'tun' });
    const lines = ['aa', 'bb'].map((id) => ({ id, alias: adapter.alias }));
    await engine.verifyEngineFiles();
    await engine.setLines(lines);
    await engine.setAppLines({ [clientExe]: 'bb' });
    engine.apiPort = await freePort();
    engine.apiSecret = randomBytes(24).toString('hex');
    const config = buildEngineConfig({ mode: 'tun', lines, ruleDir: dir,
      apiPort: engine.apiPort, apiSecret: engine.apiSecret });
    config.route.rules.unshift({ ip_cidr: [`${destination}/32`], network: 'udp', port: 53,
      action: 'route-options', override_address: adapter.ipv4, override_port: port });
    await writeFile(engine.configPath, JSON.stringify(config, null, 2));
    child = spawn(engine.singBoxPath, ['run', '-c', engine.configPath, '--disable-color'], {
      cwd: dir, windowsHide: true, stdio: ['ignore', 'pipe', 'pipe'],
    });
    child.stdout.on('data', (chunk) => { output += chunk; });
    child.stderr.on('data', (chunk) => { output += chunk; });
    child.on('error', (error) => { output += `${error.stack}\n`; });
    // waitUntilReady also rejects a child which exits before the API answers.
    engine.child = child;
    await engine.waitUntilReady(child);
    for (const size of [64, 1800]) {
      const result = await client('udp', { size, server: destination });
      assert.equal(result.received, size, 'TUN UDP reply changed size');
      let connection;
      const deadline = Date.now() + 10000;
      do {
        const all = await engine.connections();
        connection = all.find((item) => Number(item.metadata.sourcePort) === result.port &&
          item.metadata.processPath?.toLowerCase() === clientExe.toLowerCase() &&
          item.metadata.network === 'udp' && item.metadata.type === 'tun/tun-in' &&
          item.chains.includes(lineOutbound('bb')));
        if (connection) break;
        await delay(200);
      } while (Date.now() < deadline);
      assert(connection, `UDP ${size} did not cross TUN through the pinned bb outbound`);
      assert.equal(responderError, undefined);
      log(`ok - UDP through TUN: ${JSON.stringify(result)}`);
      log(`UDP route evidence: ${JSON.stringify(connection)}`);
    }
    assert.deepEqual(received.map((item) => item.bytes), [64, 1800, 64, 1800], 'Responder must receive every full datagram exactly once');
  } catch (error) {
    log(`UDP fixture engine output:\n${output || '(empty)'}`);
    throw error;
  } finally {
    if (child?.pid && child.exitCode === null && child.signalCode === null) {
      const exited = once(child, 'exit');
      child.kill();
      await Promise.race([exited, delay(10000, undefined, { ref: false }).then(() => {
        throw new Error(`UDP fixture process ${child.pid} did not exit`);
      })]);
    }
    await new Promise((resolve) => responder.close(resolve));
    await writeFile(path.join(dir, 'engine.log'), output || '[test] No engine warnings.\n');
  }
}
