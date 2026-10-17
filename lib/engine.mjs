import { spawn } from 'node:child_process';
import { createHash, randomBytes } from 'node:crypto';
import { EventEmitter, once } from 'node:events';
import { createReadStream } from 'node:fs';
import { readFile, realpath, rm, stat, writeFile } from 'node:fs/promises';
import { createServer } from 'node:net';
import path from 'node:path';
import { createInterface } from 'node:readline';
import { setTimeout as delay } from 'node:timers/promises';
import {
  appKey,
  isFallbackConnection,
  MAIN_LANE_SELECTOR,
  MAIN_OUTBOUND,
  SECOND_LANE_SELECTOR,
  SECOND_OUTBOUND,
} from './apps.mjs';
import { createLog } from './logfile.mjs';
import { killTree, runPowerShell } from './ps.mjs';
import { TUN_NAME } from './network.mjs';
import { writeFileAtomic } from './settings.mjs';

export { MAIN_LANE_SELECTOR, SECOND_LANE_SELECTOR };
export const RULE_SET_TAG = 'second-apps';
// Closing the connections stuck on the other line gets this long in all.
const RELEASE_BUDGET_MS = 8000;
// The engine's log, kept to this size; the previous run's log stays beside it.
const ENGINE_LOG_MAX_BYTES = 5 * 1024 * 1024;
// A stopped engine gets this long to exit before it is ended by force, and this
// long again after that.
const STOP_WAIT_MS = 5000;
const FORCE_STOP_WAIT_MS = 3000;

// Whether a line reaches the internet is tested through that line's own
// outbound. The addresses are IP addresses, because a name would be looked up
// through whichever line Windows prefers, so a line whose router has lost its
// internet could make both lines' tests fail. sing-box 1.14 only follows HTTPS
// addresses here: it quietly swaps any other for its own Google default. The
// second address, at another company, is only asked when the first fails, so
// one site being down or blocked is not a dead line.
export const PROBE_URLS = ['https://1.1.1.1/cdn-cgi/trace', 'https://8.8.8.8/'];
// An HTTPS test takes about four round trips. On a line that is busy with a
// big download, one round trip can reach a second or two, so a shorter limit
// failed tests on lines that worked (seen as 6-second "outages" in the log).
const PROBE_TIMEOUT_MS = 10_000;

// Placeholder so the rule-set is never empty when no app is on the second connection.
const NO_APP_PATH = 'C:\\NetSwitch\\no-app-selected.exe';

// Combining both lines sends about half of all new connections to the second
// connection, chosen by the app's source port. sing-box sees the port Windows
// gave the app's socket, and Windows hands ports out in order: one after the
// other for a burst of connections, every other one when each app connection
// is followed by the engine's own outbound socket. The low bit of the port's
// Gray code splits every aligned block of four ports two and two, and every
// pair two apart one and one, so both patterns alternate lines; a hash of the
// block flips whole blocks, so wider steps don't all land on one line.
const FIRST_COMBINED_PORT = 1024;
const LAST_PORT = 65535;

function mix32(value) {
  let n = Math.imul((value >>> 16) ^ value, 0x45d9f3b);
  n = Math.imul((n >>> 16) ^ n, 0x45d9f3b);
  return ((n >>> 16) ^ n) >>> 0;
}

export function portUsesSecond(port) {
  return (((port ^ (port >> 1)) & 1) ^ (mix32(port >> 2) & 1)) === 1;
}

let secondPorts = null;

// About 32,000 ports; built once, shared by every rule-set write.
export function combinedSecondPorts() {
  if (!secondPorts) {
    secondPorts = [];
    for (let port = FIRST_COMBINED_PORT; port <= LAST_PORT; port += 1) {
      if (portUsesSecond(port)) secondPorts.push(port);
    }
  }
  return secondPorts;
}

// Windows paths ignore letter case, and Windows doesn't always report a
// program's path in the same case, so an app's rule matches it in any case.
// Go's regular expressions escape the same characters as JavaScript's.
export function exactPathPattern(programPath) {
  return `(?i)^${programPath.replace(/[\\^$.*+?()[\]{}|]/g, '\\$&')}$`;
}

// Local networks stay on normal Windows routing: router pages, printers,
// Hyper-V and other devices on either router keep working.
export const LOCAL_RANGES = [
  '10.0.0.0/8',
  '172.16.0.0/12',
  '192.168.0.0/16',
  '169.254.0.0/16',
  '224.0.0.0/4',
  '255.255.255.255/32',
  'fc00::/7',
  'fe80::/10',
  'ff00::/8',
];

// Everything this rule-set matches goes to the second connection: the apps
// moved there, and while combining, the share of every other app's new
// connections. Both go through the second-lane selector, so they use the cable
// while the second connection is down. Apps kept on the cable are left out of
// that share, so they stay on the cable while combining. sing-box refuses a
// rule that is only "not these apps", so that condition is added only when
// there are such apps.
export function buildRuleSet(secondAppPaths, { combine = false, cableAppPaths = [] } = {}) {
  const rules = [
    secondAppPaths.length > 0
      ? { process_path_regex: secondAppPaths.map(exactPathPattern) }
      : { process_path: [NO_APP_PATH] },
  ];
  if (combine) {
    const share = { source_port: combinedSecondPorts() };
    rules.push(
      cableAppPaths.length > 0
        ? {
            type: 'logical',
            mode: 'and',
            // The port first: it rules out half the connections before the
            // path is matched at all.
            rules: [share, { process_path_regex: cableAppPaths.map(exactPathPattern), invert: true }],
          }
        : share,
    );
  }
  return { version: 3, rules };
}

export function buildEngineConfig({ mode, mainAlias, secondAlias, apiPort, apiSecret, proxyPort, ruleSetPath }) {
  const inbound =
    mode === 'tun'
      ? {
          type: 'tun',
          tag: 'tun-in',
          interface_name: TUN_NAME,
          address: ['198.18.0.1/30', 'fdfe:dcba:9876::1/126'],
          mtu: 9000,
          auto_route: true,
          strict_route: false,
          route_exclude_address: LOCAL_RANGES,
          // Leave Windows DNS settings alone (1.14 defaults to hijacking DNS).
          dns_mode: 'disabled',
          // The default system stack adds a permanent Windows Firewall rule;
          // the gVisor stack needs none. Revisit when upgrading past 1.14.
          stack: 'gvisor',
        }
      : { type: 'mixed', tag: 'mixed-in', listen: '127.0.0.1', listen_port: proxyPort };

  const outbounds = [{ type: 'direct', tag: MAIN_OUTBOUND, bind_interface: mainAlias }];
  // A known limitation: routing is IPv4 only. The outbounds are bound to the
  // lines' IPv4 setup, yet the TUN's IPv6 route makes apps try IPv6 and wait
  // 5 s for each attempt. Refusing IPv6 before the handshake makes
  // them use IPv4 at once; no_drop keeps it a refusal even after many attempts.
  const rules = mode === 'tun' ? [{ ip_version: 6, action: 'reject', no_drop: true }] : [];
  // Without a second connection, apps moved to it simply use the cable.
  // With one, each line's traffic goes through a selector, so it can use the
  // other line while its own is down: the second connection's apps fall back
  // to the cable, and everything else falls back to the second connection.
  if (secondAlias) {
    outbounds.push(
      { type: 'direct', tag: SECOND_OUTBOUND, bind_interface: secondAlias },
      {
        type: 'selector',
        tag: SECOND_LANE_SELECTOR,
        outbounds: [SECOND_OUTBOUND, MAIN_OUTBOUND],
        default: SECOND_OUTBOUND,
        interrupt_exist_connections: false,
      },
      {
        type: 'selector',
        tag: MAIN_LANE_SELECTOR,
        outbounds: [MAIN_OUTBOUND, SECOND_OUTBOUND],
        default: MAIN_OUTBOUND,
        interrupt_exist_connections: false,
      },
    );
    rules.push({ rule_set: RULE_SET_TAG, action: 'route', outbound: SECOND_LANE_SELECTOR });
  }

  return {
    // No output file: the engine's lines come to Net Switch, which keeps the
    // log to a set size.
    log: { level: 'warn', timestamp: true },
    dns: { servers: [{ type: 'local', tag: 'local' }] },
    inbounds: [inbound],
    outbounds,
    route: {
      rules,
      rule_set: [{ type: 'local', tag: RULE_SET_TAG, format: 'source', path: ruleSetPath }],
      final: secondAlias ? MAIN_LANE_SELECTOR : MAIN_OUTBOUND,
      auto_detect_interface: true,
      find_process: true,
      default_domain_resolver: 'local',
    },
    experimental: {
      clash_api: { external_controller: `127.0.0.1:${apiPort}`, secret: apiSecret },
    },
  };
}

export function freePort() {
  return new Promise((resolve, reject) => {
    const server = createServer();
    server.unref();
    server.on('error', reject);
    server.listen(0, '127.0.0.1', () => {
      const { port } = server.address();
      server.close(() => resolve(port));
    });
  });
}

function serialQueue() {
  let tail = Promise.resolve();
  return (task) => {
    const result = tail.then(task, task);
    tail = result.catch(() => {});
    return result;
  };
}

function sha256File(file) {
  return new Promise((resolve, reject) => {
    const hash = createHash('sha256');
    createReadStream(file)
      .on('error', reject)
      .on('data', (chunk) => hash.update(chunk))
      .on('end', () => resolve(hash.digest('hex')));
  });
}

// "<sha-256>  <file name>" lines, as in engine/SHA256SUMS.txt.
export function parseChecksums(text) {
  const sums = [];
  for (const line of String(text ?? '').split(/\r?\n/)) {
    const match = /^([0-9a-f]{64})\s+\*?(\S+)\s*$/i.exec(line);
    if (match) sums.push({ hash: match[1].toLowerCase(), name: match[2] });
  }
  return sums;
}

export class Engine extends EventEmitter {
  constructor({ singBoxPath, dataDir, mode, helperPath = null, spawnGuard = spawn }) {
    super();
    this.singBoxPath = singBoxPath;
    this.mode = mode;
    this.configPath = path.join(dataDir, 'engine-config.json');
    this.ruleSetPath = path.join(dataDir, 'second-apps.json');
    this.logPath = path.join(dataDir, 'engine.log');
    this.log = createLog(this.logPath, { maxBytes: ENGINE_LOG_MAX_BYTES, timestamp: false });
    this.pidPath = path.join(dataDir, 'engine.pid');
    this.dataDir = dataDir;
    this.status = 'off';
    this.error = null;
    this.child = null;
    this.helperPath = helperPath;
    this.spawnGuard = spawnGuard;
    this.guard = null;
    this.output = [];
    this.proxyPort = null;
    this.startedWith = null;
    this.secondAppPaths = [];
    this.cableAppPaths = [];
    this.combine = false;
    // Engine files already checked against their checksums, by size and time.
    this.verified = new Map();
    // Start and stop never overlap: a stop that arrives mid-start waits for it.
    this.lifecycle = serialQueue();
    // Rule-set writes are ordered and always write the latest list.
    this.ruleWrites = serialQueue();
  }

  setStatus(status, error = null) {
    this.status = status;
    this.error = error;
    this.emit('status', status);
  }

  setSecondApps(secondAppPaths) {
    return this.changeRules({ secondAppPaths: [...secondAppPaths] });
  }

  // Both lists in one write, so an app moved from one to the other is never
  // briefly in both or in neither.
  setAppLanes(secondAppPaths, cableAppPaths) {
    return this.changeRules({ secondAppPaths: [...secondAppPaths], cableAppPaths: [...cableAppPaths] });
  }

  setCombine(combine) {
    return this.changeRules({ combine });
  }

  flushRuleSet() {
    return this.changeRules({});
  }

  // The rules in memory change only once the file is written, so a write that
  // failed never slips into the next change. The combined port list is about
  // 190 KB as JSON, so that file is written compactly.
  changeRules(changes) {
    return this.ruleWrites(async () => {
      const next = { secondAppPaths: this.secondAppPaths, cableAppPaths: this.cableAppPaths, combine: this.combine, ...changes };
      const ruleSet = buildRuleSet(next.secondAppPaths, { combine: next.combine, cableAppPaths: next.cableAppPaths });
      await writeFileAtomic(this.ruleSetPath, JSON.stringify(ruleSet, null, next.combine ? undefined : 2));
      this.secondAppPaths = next.secondAppPaths;
      this.cableAppPaths = next.cableAppPaths;
      this.combine = next.combine;
    });
  }

  start(options) {
    return this.lifecycle(() => this.startNow(options));
  }

  stop() {
    return this.lifecycle(() => this.stopNow());
  }

  async startNow({ mainAlias, secondAlias }) {
    if (this.status === 'on') return;
    if (!mainAlias) {
      this.setStatus('error', 'No cable connection was found. Plug in the cable, then turn routing on.');
      return;
    }
    this.setStatus('starting');
    // Only this attempt's engine lines may explain why it failed.
    this.output = [];
    try {
      // First, so an engine left by an earlier run is stopped even when this
      // start fails its checks.
      await this.stopOrphan();
      await this.verifyEngineFiles();
      this.apiPort = await freePort();
      this.apiSecret = randomBytes(24).toString('hex');
      this.proxyPort = this.mode === 'proxy' ? await freePort() : null;
      await this.flushRuleSet();
      const config = buildEngineConfig({
        mode: this.mode,
        mainAlias,
        secondAlias,
        apiPort: this.apiPort,
        apiSecret: this.apiSecret,
        proxyPort: this.proxyPort,
        ruleSetPath: this.ruleSetPath,
      });
      await writeFile(this.configPath, JSON.stringify(config, null, 2));
      // The previous run's log is kept beside the new one, so whatever ended
      // that run can still be read.
      await this.log.rotate();

      // QueryFullProcessImageName resolves directory junctions. The guard
      // must compare with that image path, not a junction used to launch it.
      const imagePath = this.helperPath ? await realpath(this.singBoxPath) : this.singBoxPath;
      const child = spawn(this.singBoxPath, ['run', '-c', this.configPath, '--disable-color'], {
        cwd: this.dataDir,
        windowsHide: true,
        stdio: ['ignore', 'pipe', 'pipe'],
      });
      this.child = child;
      const collect = (chunk) => {
        const lines = chunk.toString().split(/\r?\n/).filter(Boolean);
        this.output.push(...lines);
        this.output = this.output.slice(-40);
        for (const line of lines) this.log.append(line);
      };
      child.stdout.on('data', collect);
      child.stderr.on('data', collect);
      child.on('exit', (code) => this.handleExit(child, code));
      child.on('error', (error) => collect(Buffer.from(error.message)));
      await this.startGuard(child, imagePath);
      await writeFile(this.pidPath, String(child.pid));

      await this.waitUntilReady(child);
      this.startedWith = { mainAlias, secondAlias };
      // Connections opened before this moment can't be inside routing.
      this.startedAt = Date.now();
      this.setStatus('on');
    } catch (error) {
      // The reason comes first; what the engine itself printed while starting
      // follows as details. Only this run's lines are used.
      const details = this.output.slice(-6).join('\n');
      await this.stopChild().catch((stopError) => {
        this.output.push(stopError.message);
      });
      this.setStatus('error', `Routing couldn't start. ${error.message}${details ? `\n${details}` : ''}`);
    }
  }

  // The engine runs as administrator, so it must be the exact sing-box the
  // checksum list names. Each file is hashed again only when it changes.
  async verifyEngineFiles() {
    const dir = path.dirname(this.singBoxPath);
    let text;
    try {
      text = await readFile(path.join(dir, 'SHA256SUMS.txt'), 'utf8');
    } catch (error) {
      if (error.code === 'ENOENT') throw new Error('engine\\SHA256SUMS.txt is missing, so the routing engine can’t be checked.');
      throw error;
    }
    const sums = parseChecksums(text);
    // A list that doesn't name the engine would check nothing.
    const exe = path.basename(this.singBoxPath).toLowerCase();
    if (!sums.some(({ name }) => name.toLowerCase() === exe)) {
      throw new Error(`engine\\SHA256SUMS.txt has no line for ${path.basename(this.singBoxPath)}, so the routing engine can’t be checked.`);
    }
    for (const { hash, name } of sums) {
      const file = path.join(dir, name);
      let info;
      try {
        info = await stat(file);
      } catch {
        throw new Error(`engine\\${name} is missing. Get it from the link in engine\\SHA256SUMS.txt.`);
      }
      const seen = `${info.size}:${info.mtimeMs}`;
      if (this.verified.get(file) === seen) continue;
      if ((await sha256File(file)) !== hash) {
        throw new Error(
          `engine\\${name} doesn’t match engine\\SHA256SUMS.txt, so it won’t be run. Get it again from the link in that file.`,
        );
      }
      this.verified.set(file, seen);
    }
  }

  async waitUntilReady(child) {
    const deadline = Date.now() + 15_000;
    while (Date.now() < deadline) {
      if (child.exitCode !== null) throw new Error('The routing engine closed while starting.');
      try {
        const response = await this.api('/version');
        if (response.ok) return;
      } catch {
        // Not listening yet.
      }
      await delay(250);
    }
    throw new Error('The routing engine did not respond within 15 seconds.');
  }

  handleExit(child, code) {
    if (this.child !== child) return;
    this.stopGuard();
    this.child = null;
    rm(this.pidPath, { force: true }).catch(() => {});
    if (this.status === 'stopping' || this.status === 'starting') return;
    const details = this.output.slice(-6).join('\n');
    this.setStatus('error', `Routing stopped unexpectedly (exit code ${code}).${details ? `\n${details}` : ''}`);
  }

  // Throws when the engine could not be stopped; routing is then still on.
  // Without an engine of its own, an engine an earlier run left behind (its
  // PID file is still there) is stopped too, so off really means off.
  async stopNow() {
    if (!this.child) {
      try {
        await this.stopOrphan();
      } catch (error) {
        this.setStatus('error', error.message);
        throw error;
      }
      this.setStatus('off');
      return;
    }
    this.setStatus('stopping');
    try {
      await this.stopChild();
    } catch (error) {
      this.setStatus('error', error.message);
      throw error;
    }
    this.setStatus('off');
  }

  // The engine is only forgotten once it has really exited. One that ignores
  // being stopped is ended by force; one that survives even that keeps its PID
  // file, so the next start can still find it.
  async stopChild() {
    const child = this.child;
    if (!child) return;
    if (child.exitCode === null && child.signalCode === null) {
      const exited = once(child, 'exit').then(() => true);
      child.kill();
      let gone = await Promise.race([exited, delay(STOP_WAIT_MS).then(() => false)]);
      if (!gone) {
        await killTree(child.pid);
        gone = await Promise.race([exited, delay(FORCE_STOP_WAIT_MS).then(() => false)]);
      }
      if (!gone) {
        throw new Error(`The routing engine (sing-box.exe, process ${child.pid}) didn’t stop. End it in Task Manager.`);
      }
    }
    this.child = null;
    this.stopGuard();
    await rm(this.pidPath, { force: true });
  }

  // An armed guard survives a hard-killed server. Keep it until the engine
  // has really exited, including when a normal stop fails.
  startGuard(child, imagePath = this.singBoxPath) {
    if (!this.helperPath || !child.pid) return Promise.resolve();
    const guard = this.spawnGuard(this.helperPath, [
      'guard', '--parent', String(process.pid), '--child', String(child.pid), '--child-path', path.resolve(imagePath),
    ], { windowsHide: true, stdio: ['ignore', 'pipe', 'pipe'] });
    this.guard = guard;
    let details = '';
    guard.stderr.on('data', (chunk) => {
      details = (details + chunk.toString()).slice(-2000);
      this.log.append(`engine guard: ${chunk.toString().trim()}`);
    });
    return new Promise((resolve, reject) => {
      const lines = createInterface({ input: guard.stdout });
      let ready = false;
      const timeout = setTimeout(() => reject(new Error('The engine guard did not become ready within 5 seconds.')), 5000);
      const fail = (reason) => {
        clearTimeout(timeout);
        lines.close();
        if (!ready) reject(new Error(`The engine guard could not start: ${reason}${details ? `: ${details.trim()}` : ''}`));
        else if (this.guard === guard && this.child === child) this.log.append(`engine guard stopped unexpectedly: ${reason}`);
      };
      guard.on('error', (error) => fail(error.message));
      guard.on('exit', (code) => fail(`exit ${code}`));
      lines.on('line', (line) => {
        if (line !== '{"ready":true}') return;
        ready = true;
        clearTimeout(timeout);
        resolve();
      });
    });
  }

  stopGuard() {
    const guard = this.guard;
    this.guard = null;
    guard?.kill();
  }

  // A previous Net Switch run may have left the engine running (for example
  // after a crash). Stop it only if that exact PID is still our sing-box.exe.
  async stopOrphan() {
    let pid;
    try {
      pid = Number.parseInt(await readFile(this.pidPath, 'utf8'), 10);
    } catch {
      return;
    }
    if (Number.isInteger(pid) && pid > 0) {
      // When the PID is gone, Get-Process still records an error that makes
      // PowerShell exit with code 1, so the script ends with an explicit exit 0.
      // A failed Stop-Process still stops the script before it gets there.
      let output;
      try {
        output = await runPowerShell(
          `$p = Get-Process -Id ${pid} -ErrorAction SilentlyContinue
if ($p -and $p.Path -eq $env:NETSWITCH_EXE) { Stop-Process -Id ${pid} -Force -ErrorAction Stop; 'stopped' }
exit 0`,
          { args: { EXE: this.singBoxPath } },
        );
      } catch (error) {
        throw new Error("Couldn't check whether the routing engine from an earlier run is still running.", {
          cause: error,
        });
      }
      if (output.includes('stopped')) await delay(1000);
    }
    await rm(this.pidPath, { force: true });
  }

  api(route, { method = 'GET', body, timeoutMs = 3000 } = {}) {
    return fetch(`http://127.0.0.1:${this.apiPort}${route}`, {
      method,
      headers: {
        Authorization: `Bearer ${this.apiSecret}`,
        ...(body ? { 'Content-Type': 'application/json' } : {}),
      },
      body: body ? JSON.stringify(body) : undefined,
      signal: AbortSignal.timeout(timeoutMs),
    });
  }

  async connections() {
    const response = await this.api('/connections');
    if (!response.ok) throw new Error(`Engine answered ${response.status}`);
    const body = await response.json();
    return body.connections ?? [];
  }

  // Ends one routed connection; the app sees it reset and may reconnect.
  async closeConnection(id) {
    const response = await this.api(`/connections/${encodeURIComponent(id)}`, { method: 'DELETE' });
    if (!response.ok && response.status !== 404) throw new Error(`Engine answered ${response.status}`);
  }

  // Points a lane's selector at an outbound: 'second' or 'cable'.
  async pointLaneAt(selector, target) {
    const route = `/proxies/${selector}`;
    const response = await this.api(route, { method: 'PUT', body: { name: target } });
    if (!response.ok) throw new Error(`Engine answered ${response.status}`);
  }

  // Does this line reach the internet? Tested through the line's own outbound,
  // so it works whichever way its apps are pointed. The round trip in ms when
  // it does, false when it doesn't, or null when the engine itself didn't
  // answer, which says nothing about the line.
  // both: ask both addresses at once instead of the second only after the
  // first failed. Used while the line is in doubt, so a verdict comes sooner;
  // a healthy line keeps asking one, which is what its data use is based on.
  async probe(outbound, { both = false } = {}) {
    if (both) {
      const results = await Promise.all(PROBE_URLS.map((url) => this.probeOnce(outbound, url)));
      const passed = results.find((result) => result !== false && result !== null);
      if (passed !== undefined) return passed;
      return results.includes(null) ? null : false;
    }
    for (const url of PROBE_URLS) {
      const result = await this.probeOnce(outbound, url);
      if (result !== false) return result;
    }
    return false;
  }

  // One test of one address: the round trip in ms (or true), false when the
  // test failed, null when the engine didn't answer.
  async probeOnce(outbound, url) {
    let response;
    try {
      response = await this.api(
        `/proxies/${encodeURIComponent(outbound)}/delay?url=${encodeURIComponent(url)}&timeout=${PROBE_TIMEOUT_MS}`,
        { timeoutMs: PROBE_TIMEOUT_MS + 3000 },
      );
    } catch {
      return null;
    }
    if (response.ok) {
      const delay = Number((await response.json().catch(() => ({}))).delay);
      return Number.isFinite(delay) && delay > 0 ? delay : true;
    }
    // 503 and 504 are the test failing; anything else is the engine.
    return response.status === 503 || response.status === 504 ? false : null;
  }

  // Would the rules send a connection to the second connection if it were
  // opened now? The moved apps, plus the share of every other app's
  // connections that combining picks by source port, except the apps kept on
  // the cable. The same rules buildRuleSet writes, and like them the program
  // path matches in any letter case.
  routesToSecond(connection) {
    const processPath = connection?.metadata?.processPath;
    const listed = (paths) => Boolean(processPath) && paths.some((item) => appKey(item) === appKey(processPath));
    if (listed(this.secondAppPaths)) return true;
    if (listed(this.cableAppPaths)) return false;
    return this.combine && portUsesSecond(Number(connection?.metadata?.sourcePort));
  }

  // Connections opened while a line was down went to the other line and stay
  // there after it is back (a selector only steers new ones). This closes
  // exactly those, so their apps open new ones, which use their own line
  // again. lane is 'second' for the second connection's apps, which fell back
  // to the cable, or 'main' for everything else, which fell back to the second
  // connection. It leaves alone connections the rules no longer send to that
  // line, because the person moved the app or changed combining meanwhile.
  // shouldContinue is asked before each close: when the line drops again,
  // closing stops. The time budget counts from the start.
  // Returns how many it found, closed and could not close, and whether it stopped early.
  async releaseFallbackConnections({ lane = 'second', budgetMs = RELEASE_BUDGET_MS, shouldContinue = () => true } = {}) {
    const until = Date.now() + budgetMs;
    const second = lane === 'second';
    const stuck = (await this.connections()).filter(
      (connection) =>
        (second
          ? isFallbackConnection(connection, SECOND_LANE_SELECTOR, MAIN_OUTBOUND)
          : isFallbackConnection(connection, MAIN_LANE_SELECTOR, SECOND_OUTBOUND)) &&
        this.routesToSecond(connection) === second,
    );
    let closed = 0;
    let failed = 0;
    let interrupted = false;
    for (const connection of stuck) {
      if (!shouldContinue()) {
        interrupted = true;
        break;
      }
      if (Date.now() > until) {
        failed += 1;
        continue;
      }
      try {
        await this.closeConnection(connection.id);
        closed += 1;
      } catch {
        failed += 1;
      }
    }
    return { found: stuck.length, closed, failed, interrupted };
  }
}
