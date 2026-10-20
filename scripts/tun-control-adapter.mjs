// The TUN harness keeps its existing engine assertions while startup and app
// choices run through the selected control service. Direct selector PUTs remain
// explicit engine tests, just as in the original harness.
import assert from 'node:assert/strict';
import { appendFile, readFile, writeFile, unlink } from 'node:fs/promises';
import path from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import { launchServer, recordServerAndEngine } from './server-under-test.mjs';
import { killTree } from '../lib/ps.mjs';
import { httpsRoute } from './tun-test-https.mjs';
import { httpsMarker } from './control-test-https.mjs';

export class ControlUnderTest {
  constructor(dataDir) {
    this.dir = dataDir;
    this.logPath = path.join(dataDir, 'engine.log');
    this.log = { append: (text) => appendFile(this.logPath, `${text}\n`) };
    this.status = 'off';
    this.error = null;
    this.appLines = {};
    this.server = null;
    this.output = '';
  }
  async api(route, body) {
    const response = await fetch(`http://127.0.0.1:${this.session.port}/api/${route}`, {
      method: body === undefined ? 'GET' : 'POST', headers: { 'X-Token': this.session.token, 'Content-Type': 'application/json' },
      body: body === undefined ? undefined : JSON.stringify(body), signal: AbortSignal.timeout(60_000),
    });
    const value = await response.json();
    if (!response.ok) throw new Error(`${route}: ${JSON.stringify(value)}`);
    return value;
  }
  async setAppLines(next) {
    if (this.session) {
      for (const file of new Set([...Object.keys(this.appLines), ...Object.keys(next)])) {
        await this.api('app-line', { path: file, line: next[file] ?? null });
      }
    }
    this.appLines = { ...next };
  }
  async start({ lines, httpsResponder }) {
    const marker = path.join(this.dir, httpsMarker);
    if (httpsResponder) await writeFile(marker, JSON.stringify(httpsRoute(httpsResponder)));
    else await unlink(marker).catch((error) => { if (error.code !== 'ENOENT') throw error; });
    if (!this.server) {
      await recordServerAndEngine();
      await writeFile(path.join(this.dir, 'settings.json'), JSON.stringify({ lines: lines.map((line) => ({ ...line, guid: null, label: line.id, kind: 'wired', metered: false, strict: false, cap: null, weight: 1 })), appLines: this.appLines, checkForUpdates: false }));
      this.server = launchServer(this.dir, 'tun');
      this.server.stdout.on('data', (b) => { this.output += b; });
      this.server.stderr.on('data', (b) => { this.output += b; });
      const deadline = Date.now() + 120_000;
      while (Date.now() < deadline && !this.session) {
        if (this.server.exitCode !== null) throw new Error(`Control exited ${this.server.exitCode}: ${this.output}`);
        try { this.session = JSON.parse(await readFile(path.join(this.dir, 'server.json'), 'utf8')); } catch { await delay(200); }
      }
      if (!this.session) throw new Error(`Control did not start: ${this.output}`);
    } else await this.api('routing', { on: true });
    const deadline = Date.now() + 120_000;
    while (Date.now() < deadline) {
      const state = await this.api('state');
      this.status = state.routing.status; this.error = state.routing.error;
      if (this.status === 'on') {
        this.config = JSON.parse(await readFile(path.join(this.dir, 'engine-config.json'), 'utf8'));
        if (httpsResponder) {
          const product = JSON.parse(await readFile(path.join(this.dir, 'traffic-product-config.json'), 'utf8'));
          const actual = structuredClone(this.config);
          assert.deepEqual(actual.route.rules.shift(), httpsRoute(httpsResponder), 'Missing local TLS destination rewrite');
          assert.deepEqual(actual, product, 'The fixture must preserve the entire selected Control configuration');
        } else {
          assert(!this.config.route.rules.some((rule) => rule.action === 'route-options'),
            'Lifecycle cycles must use the ordinary product configuration');
        }
        return;
      }
      await delay(200);
    }
    throw new Error(`Routing did not start: ${this.error}; ${this.output}`);
  }
  async engineAPI(route, method = 'GET', body) {
    const { external_controller: address, secret } = this.config.experimental.clash_api;
    const response = await fetch(`http://${address}${route}`, { method, headers: { Authorization: `Bearer ${secret}`, 'Content-Type': 'application/json' }, body: body && JSON.stringify(body), signal: AbortSignal.timeout(5000) });
    if (!response.ok) { this.status = 'error'; throw new Error(`Engine ${route}: ${response.status}`); }
    return response;
  }
  async connections() { return (await (await this.engineAPI('/connections')).json()).connections ?? []; }
  async pointLaneAt(line, target) { await this.engineAPI(`/proxies/lane-${line}`, 'PUT', { name: `line-${target}` }); }
  async stop() { if (!this.session) return; await this.api('routing', { on: false }); this.status = 'off'; }
  async quit() {
    if (!this.server) return;
    try {
      if (this.server.exitCode === null && this.session) await this.api('quit', {});
      const deadline = Date.now() + 30_000;
      while (this.server.exitCode === null && Date.now() < deadline) await delay(100);
      if (this.server.exitCode === null) throw new Error(`Control failed to quit: ${this.output}`);
      if (this.server.exitCode !== 0) throw new Error(`Control exited ${this.server.exitCode}: ${this.output}`);
    } finally {
      // A failed stop/quit must not leave inherited output pipes holding the
      // test runner open until Actions' job timeout. This is only our child.
      if (this.server.exitCode === null) await killTree(this.server.pid);
    }
  }
}
