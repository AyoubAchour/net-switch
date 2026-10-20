// Hosted-runner fixture only. Like tun-test-udp.mjs, add a non-final destination
// rewrite, leaving the product's process rules, selectors and outbounds intact.
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { once } from 'node:events';
import { writeFile } from 'node:fs/promises';
import { createServer } from 'node:https';
import path from 'node:path';
import { buildEngineConfig, freePort } from '../lib/engine.mjs';
import { hostedOnly, run } from '../tests/windows/testisp/harness.mjs';

export async function localHttps(address) {
  hostedOnly();
  const passphrase = randomBytes(24).toString('hex');
  const result = await run('powershell.exe', ['-NoProfile', '-ExecutionPolicy', 'Bypass', '-File',
    path.resolve('scripts/tun-test-certificate.ps1')], {
    // Control runs under pwsh. Let Windows PowerShell build its own module path
    // so its Security provider can mount Cert:, rather than inheriting PS7's.
    env: { NETSWITCH_TEST_CERT_PASSWORD: passphrase, PSModulePath: undefined },
  });
  const identity = JSON.parse(result.stdout);
  const ca = `-----BEGIN CERTIFICATE-----\n${identity.cert}\n-----END CERTIFICATE-----\n`;
  const seen = [];
  let next = 0;
  const sockets = new WeakMap();
  const server = createServer({ pfx: Buffer.from(identity.pfx, 'base64'), passphrase }, (req, res) => {
    if (!sockets.has(req.socket)) sockets.set(req.socket, ++next);
    const observation = { nonce: new URL(req.url, 'https://netswitch.invalid').searchParams.get('nonce'),
      connection: sockets.get(req.socket), source: req.socket.remoteAddress };
    seen.push(observation);
    res.setHeader('Content-Type', 'application/json');
    res.end(JSON.stringify(observation));
  });
  // The test, not a server idle timeout, decides when the 100 sockets close.
  server.keepAliveTimeout = 180_000;
  server.headersTimeout = 185_000;
  server.listen(0, address);
  await once(server, 'listening');
  return {
    target: { host: '203.0.113.44', port: 443, servername: 'netswitch.invalid', ca },
    address, port: server.address().port, seen,
    async close() { server.closeAllConnections(); await new Promise((resolve) => server.close(resolve)); },
  };
}

export async function startTrafficEngine(engine, lines, responder) {
  hostedOnly();
  assert.equal(engine.child, null);
  engine.setStatus('starting');
  await engine.verifyEngineFiles();
  await engine.setLines(lines);
  engine.apiPort = await freePort();
  engine.apiSecret = randomBytes(24).toString('hex');
  const config = buildEngineConfig({ mode: 'tun', lines, ruleDir: engine.ruleDir,
    apiPort: engine.apiPort, apiSecret: engine.apiSecret });
  config.route.rules.unshift(httpsRoute(responder));
  await writeFile(engine.configPath, JSON.stringify(config, null, 2));
  await engine.log.rotate();
  const child = spawn(engine.singBoxPath, ['run', '-c', engine.configPath, '--disable-color'], {
    cwd: engine.dataDir, windowsHide: true, stdio: ['ignore', 'pipe', 'pipe'],
  });
  engine.child = child;
  const collect = (chunk) => {
    const lines = chunk.toString().split(/\r?\n/).filter(Boolean);
    engine.output.push(...lines);
    engine.output = engine.output.slice(-40);
    for (const line of lines) engine.log.append(line);
  };
  child.stdout.on('data', collect);
  child.stderr.on('data', collect);
  child.on('error', (error) => collect(Buffer.from(error.stack)));
  child.on('exit', (code) => engine.handleExit(child, code));
  await writeFile(engine.pidPath, String(child.pid));
  await engine.waitUntilReady(child);
  engine.setStatus('on');
}

export function httpsRoute(responder) {
  return { ip_cidr: [`${responder.target.host}/32`], network: 'tcp', port: 443,
    action: 'route-options', override_address: responder.address, override_port: responder.port };
}
