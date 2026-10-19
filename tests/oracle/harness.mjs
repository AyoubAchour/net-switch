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

export async function oracle({ initial = {}, mode = 'tun' } = {}) {
  assert.ok(vm.SourceTextModule, 'Run with --experimental-vm-modules');
  const outputs = [];
  const files = new Map([['/oracle/package.json', await readFile(new URL('package.json', root), 'utf8')],
    ['/oracle/data/settings.json', JSON.stringify(initial)]]);
  const environment = { now: Date.UTC(2026, 9, 19, 12), adapters: [], interfaces: {}, rates: {}, counters: {}, connections: [], policy: 1 };
  let sequence = 0;
  let httpHandler;
  const emit = (kind, value) => outputs.push({ kind, ...clone(value) });
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
  const timers = [];
  class ClockDate extends Date {
    constructor(...args) { super(...(args.length ? args : [environment.now])); }
    static now() { return environment.now; }
  }
  const context = vm.createContext({ Buffer, URL, AbortSignal, Date: ClockDate,
    structuredClone: (value) => vm.runInContext(`JSON.parse(${JSON.stringify(JSON.stringify(value))})`, context),
    setTimeout: (run, ms) => { const timer = { run, at: environment.now + ms, unref() { return this; } }; timers.push(timer); return timer; },
    clearTimeout: (timer) => { const index = timers.indexOf(timer); if (index >= 0) timers.splice(index, 1); },
    setInterval: forbidden('setInterval'), clearInterval: () => {},
    console: { log: (text) => emit('console', { text }) },
    process: { argv: ['node', '/oracle/server.mjs', ...(mode === 'proxy' ? ['--dev-proxy'] : [])],
      pid: 123, execPath: '/oracle/node', platform: 'win32', arch: 'x64', env: {},
      on: () => {}, exit: (code) => emit('exit', { code }) },
    fetch: async (url, options = {}) => {
      const route = new URL(url).pathname;
      emit('engine', { route, method: options.method ?? 'GET', ...(options.body ? { body: JSON.parse(options.body) } : {}) });
      const body = route === '/connections' ? { connections: environment.connections }
        : route.endsWith('/delay') ? { delay: 18 } : {};
      return { ok: true, status: 200, json: async () => clone(body) };
    },
  });
  const socket = () => Object.assign(new EventEmitter(), {
    listen(...args) { this.port = typeof args[0] === 'number' ? args[0] || 49000 : args[0].port; args.at(-1)(); },
    address() { return { port: this.port }; }, unref() {}, close(done) { done?.(); },
  });
  class Monitor extends EventEmitter {
    start() {} stop() {} isFresh() { return true; }
    rate(alias) { return environment.rates[alias] ?? null; }
    counters(alias) { return environment.counters[alias] ?? null; }
  }
  const platform = {
    appPath: windowsAppPath, engineFileName: 'sing-box.exe', noAppPath: 'C:\\NetSwitch\\no-app-selected.exe',
    tunOptions: () => ({}), requiredEngineFiles: () => [],
    detectAdapters: async () => clone(environment.adapters), isElevated: async () => true,
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
    createInstalledApps: () => ({ list: async () => [{ path: 'C:\\Apps\\Firefox.exe', name: 'Firefox' }] }),
  };
  const mocks = new Map(Object.entries({
    'node:crypto': { createHash, timingSafeEqual, randomBytes: (size) => Buffer.alloc(size, ++sequence % 256), randomUUID: () => `oracle-${++sequence}` },
    'node:fs/promises': fs,
    'node:fs': { appendFileSync: fileWrite, createReadStream: forbidden('read stream') },
    'node:path': { default: path.posix },
    'node:url': { fileURLToPath: (url) => new URL(url).pathname },
    'node:events': { EventEmitter, once },
    'node:os': { networkInterfaces: () => clone(environment.interfaces) },
    'node:timers/promises': { setTimeout: (ms) => ms >= 1000 ? new Promise(() => {}) : Promise.resolve() },
    'node:net': { createServer: socket },
    'node:http': { createServer: (handler) => { httpHandler = handler; return socket(); } },
    'node:child_process': { spawn: (exe, args) => {
      assert.equal(exe, '/oracle/engine/sing-box.exe');
      emit('spawn', { exe, args });
      const child = Object.assign(new EventEmitter(), { pid: 456, exitCode: null, signalCode: null, stdout: new EventEmitter(), stderr: new EventEmitter() });
      child.kill = () => { child.exitCode = 0; child.emit('exit', 0); };
      return child;
    } },
    '/oracle/lib/platform/windows.mjs': { windows: platform },
    '/oracle/lib/platform/index.mjs': { platformFor: () => platform },
    '/oracle/lib/platform/windows-network.mjs': { restoreMetrics: async () => {}, restoreMinimizeConnectionsPolicy: async (value) => { environment.policy = value; } },
    '/oracle/lib/architecture.mjs': { nativeArchitecture: () => 'x64' },
    '/oracle/lib/logfile.mjs': { createLog: () => ({ append: async (text) => emit('log', { text }), rotate: async () => {} }) },
    '/oracle/lib/monitor.mjs': { findHelper: () => null, LineMonitor: Monitor },
    '/oracle/lib/helper.mjs': { NetworkMonitor: Monitor, NetworkUpdates: class {}, quickProbe: async () => ({ ok: true, ms: 18 }), readNetworkOnce: forbidden('helper'), readPolicyOnce: async () => environment.policy },
    '/oracle/lib/updates.mjs': { UpdateChecker: class { offer = null; start() {} stop() {} async check() { return 'current'; } } },
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
      let source = await readFile(new URL(name.slice('/oracle/'.length), root), 'utf8');
      // Observation hooks only; no existing statement is changed or skipped.
      if (name === '/oracle/server.mjs') source += '\n' + await readFile(new URL('tests/oracle/hooks.txt', root), 'utf8');
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
  const { Engine } = await evaluate('/oracle/lib/engine.mjs');
  // Binary verification is covered by engine tests. No executable exists here.
  Engine.prototype.verifyEngineFiles = async () => {};
  const server = await evaluate('/oracle/server.mjs');
  const settle = async () => { for (let n = 0; n < 100; n++) await Promise.resolve(); };
  await settle();
  return {
    environment, outputs, files, server, settle,
    async request(method, route, body, headers = {}) {
      let response;
      const session = JSON.parse(files.get('/oracle/data/server.json') ?? files.get('/oracle/data-test/server.json'));
      const request = { method, url: route, headers: { host: `127.0.0.1:${session.port}`, 'x-token': session.token, ...headers },
        async *[Symbol.asyncIterator]() { if (body !== undefined) yield Buffer.from(typeof body === 'string' ? body : JSON.stringify(body)); } };
      await httpHandler(request, {
        writeHead(status, headers) { response = { status, headers }; },
        end(text) { response.body = JSON.parse(text); },
      });
      await settle();
      return clone(response);
    },
  };
}
