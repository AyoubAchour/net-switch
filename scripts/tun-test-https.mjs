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

// The harness default of 60 s expired in job 120165918557 on windows-11-arm.
// Apart from the cold powershell.exe start, this call loads the PKI module
// that mounts Cert:, so it needs more room than a plain command. The job
// warms powershell.exe first; this deadline also covers that first load.
const CERTIFICATE_TIMEOUT_MS = 120_000;

export async function localHttps(address) {
  hostedOnly();
  const passphrase = randomBytes(24).toString('hex');
  const started = Date.now();
  const result = await run('powershell.exe', ['-NoProfile', '-ExecutionPolicy', 'Bypass', '-File',
    path.resolve('scripts/tun-test-certificate.ps1')], {
    timeout: CERTIFICATE_TIMEOUT_MS,
    // Control runs under pwsh. Let Windows PowerShell build its own module path
    // so its Security provider can mount Cert:, rather than inheriting PS7's.
    env: { NETSWITCH_TEST_CERT_PASSWORD: passphrase, PSModulePath: undefined },
  });
  console.log(`TLS certificate ready in ${Date.now() - started} ms`);
  const identity = JSON.parse(result.stdout);
  const ca = `-----BEGIN CERTIFICATE-----\n${identity.cert}\n-----END CERTIFICATE-----\n`;
  const seen = [];
  const events = [];
  let next = 0;
  const sockets = new WeakMap();
  let closing = false;
  function observe(socket) {
    if (sockets.has(socket)) return sockets.get(socket);
    const connection = ++next;
    sockets.set(socket, connection);
    const source = socket.remoteAddress, sourcePort = socket.remotePort;
    const event = (name, extra = {}) => {
      const detail = { at: new Date().toISOString(), connection, source, sourcePort, event: name, ...extra };
      events.push(detail);
      console.log(`TLS responder: ${JSON.stringify(detail)}`);
    };
    event('secureConnection');
    socket.on('end', () => event('peer FIN'));
    socket.on('error', (error) => event('error', { code: error.code, message: error.message }));
    socket.on('close', (hadError) => event('close', { hadError, requestedByTest: closing }));
    return connection;
  }
  const server = createServer({ pfx: Buffer.from(identity.pfx, 'base64'), passphrase }, (req, res) => {
    const observation = { nonce: new URL(req.url, 'https://netswitch.invalid').searchParams.get('nonce'),
      connection: observe(req.socket), source: req.socket.remoteAddress, sourcePort: req.socket.remotePort };
    seen.push(observation);
    res.setHeader('Content-Type', 'application/json');
    res.end(JSON.stringify(observation));
  });
  server.on('secureConnection', observe);
  server.on('tlsClientError', (error, socket) => {
    console.log(`TLS responder handshake error: ${JSON.stringify({ at: new Date().toISOString(),
      source: socket.remoteAddress, sourcePort: socket.remotePort, code: error.code, message: error.message })}`);
  });
  // The test, not a server idle timeout, decides when the 100 sockets close.
  server.keepAliveTimeout = 180_000;
  server.headersTimeout = 185_000;
  server.listen(0, address);
  await once(server, 'listening');
  return {
    target: { host: '203.0.113.44', port: 443, servername: 'netswitch.invalid', ca },
    address, port: server.address().port, seen, events,
    async close() { closing = true; server.closeAllConnections(); await new Promise((resolve) => server.close(resolve)); },
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
  config.log.level = 'info';
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
