import { spawn } from 'node:child_process';
import { createHash, randomBytes } from 'node:crypto';
import { EventEmitter, once } from 'node:events';
import { createReadStream } from 'node:fs';
import { readdir, readFile, rm, stat, writeFile } from 'node:fs/promises';
import { createServer } from 'node:net';
import path from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import { appKey, appPins, laneSelector, lineOutbound } from './apps.mjs';
import { appPathPattern } from './app-path.mjs';
import { assignPorts, FIRST_SHARED_PORT, lineForPort } from './lines.mjs';
import { createLog } from './logfile.mjs';
import { nativeArchitecture } from './architecture.mjs';
import { windows } from './platform/windows.mjs';
import { TUN_NAME } from './network.mjs';
import { writeFileAtomic } from './settings.mjs';

export { appPathPattern } from './app-path.mjs';

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
const KNOWN_PROBE_URLS = { '1.1.1.1:443': PROBE_URLS[0], '8.8.8.8:443': PROBE_URLS[1] };

// The HTTPS tests for the person's test addresses (address:port, see
// settings.probeTargets): the known ones keep their small pages, others get
// their front page.
export function probeUrls(targets) {
  const urls = (targets ?? []).map((target) => KNOWN_PROBE_URLS[target] ?? `https://${String(target).replace(/:443$/, '')}/`);
  return urls.length > 0 ? urls : PROBE_URLS;
}
// An HTTPS test takes about four round trips. On a line that is busy with a
// big download, one round trip can reach a second or two, so a shorter limit
// failed tests on lines that worked (seen as 6-second "outages" in the log).
const PROBE_TIMEOUT_MS = 10_000;

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

// The rule files, by tag. Every line has apps-<id>: the apps pinned to it.
// Every line but the main one also has share-<id>: while combining, its share
// of the other apps' new connections, picked by source port. The main line
// needs no share file: whatever no rule matches goes to it.
// Every line but the main one also has cut-<id>: its pinned apps while it is
// out of data with no other line to take them, whose new connections are
// refused rather than spend data past the cap.
export function ruleSetTags(lines) {
  return lines.flatMap((line, index) =>
    index === 0 ? [`apps-${line.id}`] : [`apps-${line.id}`, `share-${line.id}`, `cut-${line.id}`],
  );
}

// appLines: { programPath: lineId }. shares: { lineId: 0..1 } over the lines
// taking part in combining; a line without a share gets no ports. blocked:
// ids of lines whose pinned apps are refused (see ruleSetTags).
export function buildRuleSets({ lines, appLines = {}, combine = false, shares = {}, blocked = [], platform = windows }) {
  // A rule set without rules is refused; this program never exists.
  const never = { process_path: [platform.noAppPath] };
  const ports = combine ? assignPorts(shares) : {};
  const pins = [...appPins(appLines, platform).values()];
  const sets = {};
  lines.forEach((line, index) => {
    const pinned = pins.filter(({ lineId }) => lineId === line.id).map(({ path }) => path);
    const apps = pinned.length > 0 ? { process_path_regex: pinned.map((programPath) => appPathPattern(programPath, platform)) } : never;
    sets[`apps-${line.id}`] = { version: 3, rules: [apps] };
    if (index > 0) {
      const own = ports[line.id] ?? [];
      sets[`share-${line.id}`] = { version: 3, rules: [own.length > 0 ? { source_port: own } : never] };
      sets[`cut-${line.id}`] = { version: 3, rules: [blocked.includes(line.id) ? apps : never] };
    }
  });
  return sets;
}

// lines: [{ id, alias }] in priority order, the main line first. ipv6:
// whether IPv6 is routed too, which needs every line to have it.
export function buildEngineConfig({ mode, lines, apiPort, apiSecret, proxyPort, ruleDir, ipv6 = false, platform = windows }) {
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
          ...platform.tunOptions({ lines, ipv6 }),
        }
      : { type: 'mixed', tag: 'mixed-in', listen: '127.0.0.1', listen_port: proxyPort };

  // One outbound per line, bound to its adapter.
  const outbounds = lines.map((line) => ({ type: 'direct', tag: lineOutbound(line.id), bind_interface: line.alias }));
  // IPv6 is routed only when every line has it: a line takes over another's
  // apps, so one without IPv6 would break their IPv6 connections. Otherwise
  // the TUN's IPv6 route would make apps try IPv6 and wait 5 s for each
  // attempt, so IPv6 is refused before the handshake and they use IPv4 at
  // once; no_drop keeps it a refusal even after many attempts.
  const rules = mode === 'tun' && !ipv6 ? [{ ip_version: 6, action: 'reject', no_drop: true }] : [];
  // With two lines or more, each line's traffic goes through its own selector,
  // which Net Switch points at another line while that line is down. Every
  // selector can reach every line; which one is allowed (not a line kept to
  // its own apps, not one out of data) is decided when it is pointed.
  const several = lines.length > 1;
  if (several) {
    for (const line of lines) {
      outbounds.push({
        type: 'selector',
        tag: laneSelector(line.id),
        outbounds: [line, ...lines.filter((other) => other.id !== line.id)].map((item) => lineOutbound(item.id)),
        default: lineOutbound(line.id),
        interrupt_exist_connections: false,
      });
    }
  }
  const to = (line) => (several ? laneSelector(line.id) : lineOutbound(line.id));
  // First match wins: apps refused for a line out of data, then pinned apps on
  // every line before any sharing, so a pinned app is never shared.
  for (const line of lines.slice(1)) rules.push({ rule_set: `cut-${line.id}`, action: 'reject' });
  for (const line of lines) rules.push({ rule_set: `apps-${line.id}`, action: 'route', outbound: to(line) });
  for (const line of lines.slice(1)) rules.push({ rule_set: `share-${line.id}`, action: 'route', outbound: to(line) });

  return {
    // No output file: the engine's lines come to Net Switch, which keeps the
    // log to a set size.
    log: { level: 'warn', timestamp: true },
    dns: { servers: [{ type: 'local', tag: 'local' }] },
    inbounds: [inbound],
    outbounds,
    route: {
      rules,
      rule_set: ruleSetTags(lines).map((tag) => ({
        type: 'local',
        tag,
        format: 'source',
        path: path.join(ruleDir, `${tag}.json`),
      })),
      final: to(lines[0]),
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
  constructor({ singBoxPath, dataDir, mode, architecture = nativeArchitecture, platform = windows }) {
    super();
    this.platform = platform;
    this.singBoxPath = singBoxPath;
    this.mode = mode;
    this.configPath = path.join(dataDir, 'engine-config.json');
    this.ruleDir = dataDir;
    this.logPath = path.join(dataDir, 'engine.log');
    this.log = createLog(this.logPath, { maxBytes: ENGINE_LOG_MAX_BYTES, timestamp: false });
    this.pidPath = path.join(dataDir, 'engine.pid');
    this.dataDir = dataDir;
    this.status = 'off';
    this.error = null;
    this.child = null;
    this.architecture = architecture;
    this.output = [];
    this.proxyPort = null;
    this.startedWith = null;
    // What the rule files say now: the lines they were written for (priority
    // order, main first), the pinned apps, combining and its shares.
    this.lines = [];
    this.appLines = {};
    this.combine = false;
    this.shares = {};
    // Lines whose pinned apps are refused while they are out of data.
    this.blocked = [];
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

  setAppLines(appLines) {
    return this.changeRules({ appLines: { ...appLines } });
  }

  setCombine(combine) {
    return this.changeRules({ combine });
  }

  setShares(shares) {
    return this.changeRules({ shares: { ...shares } });
  }

  // The lines the next start binds. Changing them needs a restart; their rule
  // files are written now so they are ready.
  setLines(lines) {
    return this.changeRules({ lines: lines.map(({ id, alias }) => ({ id, alias })) });
  }

  flushRuleSet() {
    return this.changeRules({});
  }

  // The rules in memory change only once every file is written, so a write
  // that failed never slips into the next change. Share files list thousands
  // of ports, so they are written compactly.
  changeRules(changes) {
    return this.ruleWrites(async () => {
      const next = {
        lines: this.lines,
        appLines: this.appLines,
        combine: this.combine,
        shares: this.shares,
        blocked: this.blocked,
        ...changes,
      };
      const write = (tag, set) =>
        writeFileAtomic(path.join(this.ruleDir, `${tag}.json`), JSON.stringify(set, null, tag.startsWith('share-') ? undefined : 2));
      const sets = buildRuleSets({ ...next, platform: this.platform });
      const written = [];
      try {
        for (const [tag, set] of Object.entries(sets)) {
          await write(tag, set);
          written.push(tag);
        }
      } catch (error) {
        // The engine reloads each file on its own, so files already written
        // would route by the new rules while the rest still say the old. They
        // are put back, so routing matches what the window shows.
        const before = buildRuleSets({
          platform: this.platform,
          lines: this.lines,
          appLines: this.appLines,
          combine: this.combine,
          shares: this.shares,
          blocked: this.blocked,
        });
        for (const tag of written) {
          if (before[tag]) await write(tag, before[tag]).catch(() => {});
        }
        throw error;
      }
      Object.assign(this, next);
    });
  }

  // Rule files of lines that no longer exist, and the single file versions
  // 0.2.0 and earlier used, are removed so they don't pile up.
  async removeStaleRuleFiles() {
    const keep = new Set(ruleSetTags(this.lines).map((tag) => `${tag}.json`));
    let names = [];
    try {
      names = await readdir(this.ruleDir);
    } catch {
      return;
    }
    for (const name of names) {
      if ((/^(apps|share|cut)-[0-9a-f]+\.json$/.test(name) && !keep.has(name)) || name === 'second-apps.json') {
        await rm(path.join(this.ruleDir, name), { force: true }).catch(() => {});
      }
    }
  }

  start(options) {
    return this.lifecycle(() => this.startNow(options));
  }

  stop() {
    return this.lifecycle(() => this.stopNow());
  }

  // lines: [{ id, alias }] in priority order, the main line first. ipv6:
  // route IPv6 too (see buildEngineConfig).
  async startNow({ lines, ipv6 = false }) {
    if (this.status === 'on') return;
    if (!lines?.length) {
      this.setStatus('error', 'No internet connection was found. Connect one, then turn routing on.');
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
      await this.setLines(lines);
      await this.removeStaleRuleFiles();
      const config = buildEngineConfig({
        platform: this.platform,
        mode: this.mode,
        lines: this.lines,
        apiPort: this.apiPort,
        apiSecret: this.apiSecret,
        proxyPort: this.proxyPort,
        ruleDir: this.ruleDir,
        ipv6,
      });
      await writeFile(this.configPath, JSON.stringify(config, null, 2));
      // The previous run's log is kept beside the new one, so whatever ended
      // that run can still be read.
      await this.log.rotate();

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
      await writeFile(this.pidPath, String(child.pid));

      await this.waitUntilReady(child);
      this.startedWith = { lines: this.lines.map(({ id, alias }) => ({ id, alias })), ipv6 };
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
  async verifyEngineFiles(arch) {
    const dir = path.dirname(this.singBoxPath);
    // A checkout has both lists. An installed payload has only its own list,
    // staged under the common name so it cannot accidentally use the other one.
    let checkout = false;
    try {
      await stat(path.join(dir, 'SHA256SUMS-arm64.txt'));
      checkout = true;
    } catch (error) {
      if (error.code !== 'ENOENT') throw error;
    }
    // fetch-engine selects Windows' real architecture. Installed copies instead
    // bundle an engine matching Node, including older x64 installs on ARM64.
    arch ??= checkout ? this.architecture() : process.arch;
    const checksumName = checkout && arch === 'arm64' ? 'SHA256SUMS-arm64.txt' : 'SHA256SUMS.txt';
    let text;
    try {
      text = await readFile(path.join(dir, checksumName), 'utf8');
    } catch (error) {
      if (error.code === 'ENOENT') throw new Error(`engine\\${checksumName} is missing, so the routing engine can’t be checked.`);
      throw error;
    }
    const sums = parseChecksums(text);
    // A list that doesn't name the engine would check nothing.
    const exe = path.basename(this.singBoxPath).toLowerCase();
    if (!sums.some(({ name }) => name.toLowerCase() === exe)) {
      throw new Error(`engine\\${checksumName} has no line for ${path.basename(this.singBoxPath)}, so the routing engine can’t be checked.`);
    }
    for (const required of this.platform.requiredEngineFiles(arch)) {
      if (!sums.some(({ name }) => name.toLowerCase() === required.toLowerCase())) {
        throw new Error(`engine\\${checksumName} has no line for ${required}, which the ${arch} engine requires.`);
      }
    }
    for (const { hash, name } of sums) {
      const file = path.join(dir, name);
      let info;
      try {
        info = await stat(file);
      } catch {
        throw new Error(`engine\\${name} is missing. Get it from the link in engine\\${checksumName}.`);
      }
      const seen = `${info.size}:${info.mtimeMs}`;
      if (this.verified.get(file) === seen) continue;
      if ((await sha256File(file)) !== hash) {
        throw new Error(
          `engine\\${name} doesn’t match engine\\${checksumName} for ${arch}, so it won’t be run. Get it again from the link in that file.`,
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
    this.child = null;
    // The serialized stop/start owns PID-file cleanup. An asynchronous delete
    // here can race stopChild or erase the next run's newly written PID.
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
        await this.platform.killTree(child.pid);
        gone = await Promise.race([exited, delay(FORCE_STOP_WAIT_MS).then(() => false)]);
      }
      if (!gone) {
        throw new Error(`The routing engine (${this.platform.engineFileName}, process ${child.pid}) didn’t stop. End it in Task Manager.`);
      }
    }
    this.child = null;
    await this.removeStoppedPidFile();
  }

  // An earlier Net Switch run may have left the engine running (for example
  // after a crash). Stop it only if that exact PID is still our sing-box.exe.
  async stopOrphan() {
    let pid;
    try {
      pid = Number.parseInt(await readFile(this.pidPath, 'utf8'), 10);
    } catch {
      return;
    }
    if (Number.isInteger(pid) && pid > 0) {
      await this.platform.stopOrphan(pid, this.singBoxPath);
    }
    await this.removeStoppedPidFile();
  }

  // Process termination succeeded before either caller gets here. Windows can
  // still deny deleting its old record; that must not cancel quit and let the
  // supervisor restart routing. A later start retains the orphan identity check.
  async removeStoppedPidFile() {
    try {
      await rm(this.pidPath, { force: true });
    } catch (error) {
      await this.log.append(`Engine stopped; could not remove PID file: ${error.message}`);
    }
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

  // Points a line's selector at a line: its own, or the one taking over.
  async pointLaneAt(lineId, targetLineId) {
    const route = `/proxies/${encodeURIComponent(laneSelector(lineId))}`;
    const response = await this.api(route, { method: 'PUT', body: { name: lineOutbound(targetLineId) } });
    if (!response.ok) throw new Error(`Engine answered ${response.status}`);
  }

  // Does this line reach the internet? Tested through the line's own outbound,
  // so it works whichever way its apps are pointed. The round trip in ms when
  // it does, false when it doesn't, or null when the engine itself didn't
  // answer, which says nothing about the line.
  // both: ask both addresses at once instead of the second only after the
  // first failed. Used while the line is in doubt, so a verdict comes sooner;
  // a healthy line keeps asking one, which is what its data use is based on.
  async probe(lineId, { both = false, urls = PROBE_URLS } = {}) {
    const outbound = lineOutbound(lineId);
    if (both) {
      const results = await Promise.all(urls.map((url) => this.probeOnce(outbound, url)));
      const passed = results.find((result) => result !== false && result !== null);
      if (passed !== undefined) return passed;
      return results.includes(null) ? null : false;
    }
    for (const url of urls) {
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

  // Which line the rules send a connection to if it were opened now, before
  // any failover: its app's pinned line; else, while combining, the line its
  // source port is shared to; else the main line. The same rules
  // buildRuleSets writes, and like them the program path matches in any
  // letter case.
  routesTo(connection) {
    if (this.lines.length === 0) return null;
    const processPath = connection?.metadata?.processPath;
    if (processPath) {
      const lineId = appPins(this.appLines, this.platform).get(appKey(processPath, this.platform))?.lineId;
      if (this.lines.some((line) => line.id === lineId)) return lineId;
    }
    // Shares exactly as the rule files used them, so a port lands on the same
    // line here; a share for a line the files don't have goes to the main line.
    const port = Number(connection?.metadata?.sourcePort);
    const shares = Object.entries(this.shares);
    if (this.combine && shares.length > 0 && port >= FIRST_SHARED_PORT) {
      const lineId = lineForPort(port, shares);
      if (this.lines.some((line) => line.id === lineId)) return lineId;
    }
    return this.lines[0].id;
  }
}
