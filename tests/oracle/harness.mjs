// Executes the unmodified server with no host I/O. Only the loader reads source.
import assert from 'node:assert/strict';
import { createHash, timingSafeEqual } from 'node:crypto';
import { EventEmitter, once } from 'node:events';
import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import vm from 'node:vm';
import { windowsAppPath } from '../../lib/platform/windows-paths.mjs';

const root = new URL('../../', import.meta.url);
const clone = (value) => JSON.parse(JSON.stringify(value));
const forbidden = (name) => () => { throw new Error(`Oracle forbids host ${name}`); };

export async function oracle({ initial = {}, mode = 'tun', importOnly = false, trace = null, environment: suppliedEnvironment = {} } = {}) {
  assert.ok(vm.SourceTextModule, 'Run with --experimental-vm-modules');
  const outputs = [];
  const files = new Map([['/oracle/package.json', await readFile(new URL('package.json', root), 'utf8')],
    ['/oracle/data/settings.json', JSON.stringify(initial)]]);
  const environment = { now: Date.UTC(2026, 9, 19, 12), adapters: [], interfaces: {}, rates: {}, counters: {}, connections: [], probes: {}, policy: 1 };
  Object.assign(environment, clone(suppliedEnvironment));
  let sequence = 0;
  let httpHandler;
  const emit = (kind, value) => { outputs.push({ kind, ...clone(value) }); trace?.('output', kind, clone(value)); };
  let operation = 0;
  const complete = (kind, value) => {
    const id = ++operation;
    trace?.('input', kind, clone(value));
    trace?.('input', 'completion', { id, kind });
    return value;
  };
  const observeAsync = (object, scope) => {
    if (!trace) return object;
    for (const [name, original] of Object.entries(object)) {
      if (original?.constructor?.name !== 'AsyncFunction') continue;
      object[name] = async (...args) => {
        try {
          const value = await original(...args);
          complete('async-result', { operation: `${scope}.${name}`, args, ok: true, value: value ?? null, undefined: value === undefined });
          return value;
        } catch (error) {
          complete('async-result', { operation: `${scope}.${name}`, args, ok: false, code: error.code ?? null, message: error.message });
          throw error;
        }
      };
    }
    return object;
  };
  const fileWrite = (name, text) => {
    const bytes = Buffer.from(text);
    files.set(name, bytes.toString());
    if (name.endsWith('.tmp')) return;
    emit('write', { file: name, bytes: bytes.length, sha256: createHash('sha256').update(bytes).digest('hex'),
      ...(!/\/share-/.test(name) ? { text: bytes.toString() } : {}) });
  };
  const missing = () => Object.assign(new Error('No such oracle file'), { code: 'ENOENT' });
  const fs = {
    readFile: async (name, encoding) => {
      if (!files.has(name)) throw missing();
      return encoding ? files.get(name) : Buffer.from(files.get(name));
    },
    writeFile: async (name, text) => fileWrite(name, text),
    appendFile: async (name, text) => fileWrite(name, (files.get(name) ?? '') + text),
    rename: async (from, to) => {
      if (!files.has(from)) throw missing();
      fileWrite(to, files.get(from)); files.delete(from);
    },
    copyFile: async (from, to) => {
      if (!files.has(from)) throw missing();
      fileWrite(to, files.get(from));
    },
    rm: async (name) => { files.delete(name); emit('remove', { file: name }); },
    mkdir: async () => {},
    readdir: async (dir) => [...files.keys()].filter((name) => path.posix.dirname(name) === dir).map(path.posix.basename),
    stat: async (name) => { if (!files.has(name)) throw missing(); return { size: Buffer.byteLength(files.get(name)), mtimeMs: 0 }; },
  };
  if (trace) {
    for (const [name, operation] of Object.entries(fs)) {
      fs[name] = async (...args) => {
        try {
          const value = await operation(...args);
          complete('file-completion', { operation: name, file: args[0], ok: true });
          return value;
        } catch (error) {
          complete('file-completion', { operation: name, file: args[0], ok: false, code: error.code ?? null });
          throw error;
        }
      };
    }
  }
  const timers = [];
  class ClockDate extends Date {
    constructor(...args) { super(...(args.length ? args : [environment.now])); }
    static now() { return environment.now; }
  }
  const context = vm.createContext({ Buffer, URL, AbortSignal, Date: ClockDate,
    oracleEvent: (event) => trace?.('output', 'event', clone(event)),
    structuredClone: (value) => vm.runInContext(`JSON.parse(${JSON.stringify(JSON.stringify(value))})`, context),
    setTimeout: (run, ms) => { const timer = { run, at: environment.now + ms, unref() { return this; } }; timers.push(timer); return timer; },
    clearTimeout: (timer) => { const index = timers.indexOf(timer); if (index >= 0) timers.splice(index, 1); },
    setInterval: forbidden('setInterval'), clearInterval: () => {},
    console: { log: (text) => emit('console', { text }) },
    process: { argv: ['node', importOnly ? '/oracle/test.mjs' : '/oracle/server.mjs', ...(mode === 'proxy' ? ['--dev-proxy'] : [])],
      pid: 123, execPath: '/oracle/node', platform: 'win32', arch: 'x64', env: {},
      on: () => {}, exit: (code) => emit('exit', { code }) },
    fetch: async (url, options = {}) => {
      const route = new URL(url).pathname;
      emit('engine', { route, method: options.method ?? 'GET', ...(options.body ? { body: JSON.parse(options.body) } : {}) });
      const probe = route.endsWith('/delay');
      const lineId = probe ? decodeURIComponent(route.split('/')[2]).slice(5) : null;
      const answer = environment.probes[lineId] ?? 18;
      const status = probe && answer === false ? 503 : 200;
      const body = route === '/connections' ? { connections: environment.connections } : probe ? { delay: answer } : {};
      complete(probe ? 'probe-result' : 'engine-reply', { route, status, body });
      return { ok: status === 200, status, ...observeAsync({ json: async () => clone(body) }, `engine.${route}`) };
    },
  });
  const socket = () => Object.assign(new EventEmitter(), {
    listen(...args) { this.port = typeof args[0] === 'number' ? args[0] || 49000 : args[0].port; complete('socket-completion', { operation: 'listen', port: this.port }); args.at(-1)(); },
    address() { return { port: this.port }; }, unref() {}, close(done) { complete('socket-completion', { operation: 'close', port: this.port }); done?.(); },
  });
  class Monitor extends EventEmitter {
    start() {} stop() {} isFresh() { return true; }
    rate(alias) { return environment.rates[alias] ?? null; }
    counters(alias) { return environment.counters[alias] ?? null; }
  }
  const platform = {
    appPath: windowsAppPath, engineFileName: 'sing-box.exe', noAppPath: 'C:\\NetSwitch\\no-app-selected.exe',
    tunOptions: () => ({}), requiredEngineFiles: () => [],
    detectAdapters: async () => complete('adapter-snapshot', clone(environment.adapters)), isElevated: async () => true,
    readDefaultRoutes: async () => Object.values(environment.interfaces).flat().filter((item) => item.family === 'IPv4').map((item) => ({ interfaceAddress: item.address })),
    readMinimizeConnectionsPolicy: async () => environment.policy,
    readMetrics: async () => [{ family: 'IPv4', automatic: true, metric: 25 }],
    allowSimultaneousConnections: async () => { environment.policy = 0; },
    applyCableAsMain: async () => {},
    closeTcpConnections: async (items) => { emit('outside-close', { items }); return { closed: items.length, failed: 0, gone: 0, codes: [] }; },
    canAutostart: () => false, disableAutostart: forbidden('autostart'), enableAutostart: forbidden('autostart'),
    installedHelper: () => null, readAutostart: async () => false, upgradeAutostart: async () => 'unchanged',
    protectMachineDir: async () => {}, portHolder: async () => null, stopOrphan: forbidden('stopOrphan'), killTree: forbidden('killTree'),
    createAppInfo: () => ({
      describe: (programPath) => ({ name: path.win32.basename(programPath, '.exe'), hasIcon: false, switchable: !!programPath, reconnectable: !!programPath && !/svchost\.exe$/i.test(programPath) }),
      lookupPending() {}, icon: () => null,
    }),
    createInstalledApps: () => observeAsync({ list: async () => [{ path: 'C:\\Apps\\Firefox.exe', name: 'Firefox' }] }, 'installedApps'),
  };
  observeAsync(platform, 'platform');
  const mocks = new Map(Object.entries({
    'node:crypto': { createHash, timingSafeEqual, randomBytes: (size) => Buffer.alloc(size, ++sequence % 256), randomUUID: () => `oracle-${++sequence}` },
    'node:fs/promises': fs,
    'node:fs': { appendFileSync: fileWrite, createReadStream: forbidden('read stream'), existsSync: (name) => files.has(name) },
    'node:readline': { createInterface: forbidden('readline') },
    'node:path': { default: path.posix },
    'node:url': { fileURLToPath: (url) => new URL(url).pathname },
    'node:events': { EventEmitter, once },
    'node:os': { networkInterfaces: () => clone(environment.interfaces) },
    'node:timers/promises': { setTimeout: (ms) => ms >= 1000 ? new Promise(() => {}) : trace ? Promise.resolve().then(() => { complete('timer-completion', { ms }); }) : Promise.resolve() },
    'node:net': { createServer: socket },
    'node:http': { createServer: (handler) => { httpHandler = handler; return socket(); } },
    'node:child_process': { spawn: (exe, args) => {
      assert.equal(exe, '/oracle/engine/sing-box.exe');
      emit('spawn', { exe, args });
      const child = Object.assign(new EventEmitter(), { pid: 456, exitCode: null, signalCode: null, stdout: new EventEmitter(), stderr: new EventEmitter() });
      child.kill = () => { child.exitCode = 0; complete('process-exit', { pid: child.pid, code: 0 }); child.emit('exit', 0); };
      return child;
    } },
    '/oracle/lib/platform/windows.mjs': { windows: platform },
    '/oracle/lib/platform/index.mjs': { platformFor: () => platform },
    '/oracle/lib/platform/windows-network.mjs': observeAsync({ restoreMetrics: async () => {}, restoreMinimizeConnectionsPolicy: async (value) => { environment.policy = value; } }, 'network'),
    '/oracle/lib/architecture.mjs': { nativeArchitecture: () => 'x64' },
    '/oracle/lib/ps.mjs': { spawnPowerShell: forbidden('PowerShell') },
    '/oracle/lib/logfile.mjs': { createLog: () => observeAsync({ append: async (text) => emit('log', { text }), rotate: async () => {} }, 'log') },
    '/oracle/lib/monitor.mjs': { findHelper: () => null, LineMonitor: Monitor },
    '/oracle/lib/helper.mjs': observeAsync({ NetworkMonitor: Monitor, NetworkUpdates: class {}, quickProbe: async () => ({ ok: true, ms: 18 }), readNetworkOnce: forbidden('helper'), readPolicyOnce: async () => environment.policy }, 'helper'),
    '/oracle/lib/updates.mjs': { UpdateChecker: class { offer = null; start() {} stop() {} async check() { complete('async-result', { operation: 'updates.check', args: [], ok: true, value: 'current', undefined: false }); return 'current'; } } },
  }));
  const modules = new Map();
  async function load(name) {
    if (modules.has(name)) return modules.get(name);
    let module;
    if (mocks.has(name)) {
      const values = mocks.get(name);
      module = new vm.SyntheticModule(Object.keys(values), function () {
        for (const [key, value] of Object.entries(values)) this.setExport(key, value);
      }, { context, identifier: name });
    } else {
      assert.ok(name.startsWith('/oracle/'), `Unapproved import: ${name}`);
      let source = await readFile(new URL(name.slice('/oracle/'.length).replace('monitor-source.mjs', 'monitor.mjs'), root), 'utf8');
      // Observation hooks only; no existing statement is changed or skipped.
      if (name === '/oracle/server.mjs') {
        const hooks = await readFile(new URL('tests/oracle/hooks.txt', root), 'utf8');
        if (source.includes('export async function createServer')) {
          source = source.replace('return { server, buildState, shutdown };', hooks.replace('export const oracleHooks =', 'globalThis.oracleHooks =') + '\nreturn { server, buildState, shutdown };');
        } else source += '\n' + hooks;
      }
      module = new vm.SourceTextModule(source, { context, identifier: name,
        initializeImportMeta(meta) { meta.url = `file://${name}`; } });
    }
    modules.set(name, module);
    return module;
  }
  async function evaluate(name) {
    const module = await load(name);
    if (module.status === 'unlinked') await module.link((specifier, parent) => load(specifier.startsWith('.') ? path.posix.resolve(path.posix.dirname(parent.identifier), specifier) : specifier));
    if (module.status === 'linked') await module.evaluate();
    return module.namespace;
  }
  Object.assign(platform, await evaluate('/oracle/lib/windows-undo.mjs'));
  if (trace) {
    const { LineMonitor } = await evaluate('/oracle/lib/monitor-source.mjs');
    mocks.get('/oracle/lib/monitor.mjs').LineMonitor = class extends LineMonitor {
      start() {} stop() {}
      counters(alias) { const value = super.counters(alias); complete('counter-sample', { alias, value }); return value; }
    };
  }
  const { Engine } = await evaluate('/oracle/lib/engine.mjs');
  // Binary verification is covered by engine tests. No executable exists here.
  Engine.prototype.verifyEngineFiles = async () => {};
  const server = await evaluate('/oracle/server.mjs');
  const settle = async () => { for (let n = 0; n < 100; n++) await Promise.resolve(); };
  await settle();
  const result = {
    environment, outputs, files, server: { ...server, oracleHooks: context.oracleHooks ?? server.oracleHooks }, settle,
    async start(options = {}) {
      const instance = await server.createServer(options);
      result.server.oracleHooks = context.oracleHooks;
      await settle();
      return instance;
    },
    async advance(ms) {
      assert.ok(Number.isFinite(ms) && ms >= 0);
      const end = environment.now + ms;
      for (let count = 0; ; count++) {
        assert.ok(count < 10000, 'Timer loop did not settle');
        timers.sort((a, b) => a.at - b.at);
        if (!timers.length || timers[0].at > end) break;
        const timer = timers.shift();
        environment.now = timer.at;
        trace?.('input', 'clock-tick', { now: environment.now });
        timer.run();
        await settle();
      }
      environment.now = end;
      trace?.('input', 'clock-tick', { now: end });
      await settle();
    },
    async request(method, route, body, headers = {}) {
      trace?.('input', 'http', { method, route, ...(body === undefined ? {} : { body: clone(body) }), headers });
      let response;
      const session = JSON.parse(files.get('/oracle/data/server.json') ?? files.get('/oracle/data-test/server.json'));
      const request = { method, url: route, headers: { host: `127.0.0.1:${session.port}`, 'x-token': session.token, ...headers },
        async *[Symbol.asyncIterator]() { if (body !== undefined) yield Buffer.from(typeof body === 'string' ? body : JSON.stringify(body)); } };
      await httpHandler(request, {
        writeHead(status, headers) { response = { status, headers }; },
        end(text) { response.body = JSON.parse(text); },
      });
      await settle();
      trace?.('output', 'api', clone(response));
      return clone(response);
    },
  };
  return result;
}
