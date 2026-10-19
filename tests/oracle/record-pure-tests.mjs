// Run the original assertions, then freeze each public call for the Go test port.
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import vm from 'node:vm';
import * as apps from '../../lib/apps.mjs';
import * as paths from '../../lib/app-path.mjs';
import * as lines from '../../lib/lines.mjs';
import * as health from '../../lib/line-health.mjs';
import * as usage from '../../lib/usage.mjs';
import * as updates from '../../lib/updates.mjs';

const all = {};
const names = { 'app-path': 'apppath', lines: 'lines', 'line-health': 'linehealth', usage: 'usage', apps: 'apps', updates: 'updates' };
for (const [file, packageName] of Object.entries(names)) {
  const cases = [];
  let current;
  let serial = 0;
  let entropy = 0;
  const references = new WeakMap();
  const encode = (value) => {
    if (value === undefined) return null;
    if (value && typeof value === 'object' && references.has(value)) return { ref: references.get(value) };
    if (value instanceof Set) return [...value];
    if (Array.isArray(value)) return value.map(encode);
    if (value && typeof value === 'object') return Object.fromEntries(Object.entries(value).map(([key, item]) => [key, encode(item)]));
    return value;
  };
  const record = (entry) => {
    if (!current) return;
    const key = JSON.stringify(entry);
    if (entry.id || !current.seen.has(key)) { current.seen.add(key); current.calls.push(entry); }
  };
  const wrap = (name, fn) => {
    if (/^[A-Z]/.test(name)) return class {
      constructor(...args) {
        const target = new fn(...args);
        const id = ++serial;
        record({ name, id, args: encode(args), result: null });
        let proxy;
        proxy = new Proxy(target, {
          get(target, key) {
            if (typeof target[key] !== 'function') return target[key];
            return (...args) => {
              const input = encode(args);
              if (name === 'Usage' && key === 'ingest') {
                input[1] = Object.fromEntries(args[0].map((line) => [line.id, args[1](line)]));
                input[2] = Object.fromEntries(args[0].map((line) => [line.id, args[2](line)]));
              }
              const result = target[key](...args);
              record({ name: String(key), id, args: input, result: result === target ? { ref: id } : encode(result),
                ...(name === 'LineHealth' ? { state: encode({ ...target }) } : {}) });
              return result === target ? proxy : result;
            };
          },
          set(target, key, value) { record({ name: 'set', id, args: [String(key), encode(value)], result: null }); target[key] = value; return true; },
        });
        references.set(proxy, id); references.set(target, id);
        return proxy;
      }
    };
    return (...args) => {
      let input = encode(args);
      if (name === 'laneTarget') input[2] = Object.fromEntries(args[0].map((line) => [line.id, args[2](line.id)]));
      if (name === 'offerFrom' && args[2] === undefined) args = [args[0], args[1], 'x64'];
      if (name === 'migrateSettings' || name === 'newLine') {
        const rng = (size) => Buffer.alloc(size, ++entropy);
        args = [...args, rng];
      }
      const result = fn(...args);
      record({ name, args: input, result: encode(result) });
      return result;
    };
  };
  const modules = {
    '../lib/apps.mjs': apps, '../lib/engine.mjs': { appPathPattern: paths.appPathPattern },
    '../lib/lines.mjs': lines, '../lib/line-health.mjs': health, '../lib/usage.mjs': usage,
    '../lib/updates.mjs': updates, '../lib/architecture.mjs': { nativeArchitecture: () => 'x64', createArchitectureReader: () => {} },
  };
  const context = vm.createContext({ console, Buffer, Date, Set, Map });
  const source = await readFile(new URL(`../../test/${file}.test.mjs`, import.meta.url), 'utf8');
  const test = (name, fn) => {
    // Port the three port-distribution loops directly in Go; recording millions
    // of repeated calls adds size without adding assertions.
    if (file === 'lines' && /every port|any eight|ports Windows/.test(name)) return;
    if (file === 'updates' && cases.length >= 5) return;
    current = { name, calls: [], seen: new Set() }; serial = 0; entropy = 0;
    fn();
    cases.push({ name, calls: current.calls }); current = null;
  };
  const root = new vm.SourceTextModule(source, { context });
  await root.link((specifier) => {
    let values;
    if (specifier === 'node:assert/strict') values = { default: Object.assign((...args) => assert(...args), assert, {
      deepEqual: (actual, expected, message) => assert.deepEqual(structuredClone(actual), structuredClone(expected), message),
    }) };
    else if (specifier === 'node:test') values = { test };
    else {
      assert.ok(modules[specifier], specifier);
      values = Object.fromEntries(Object.entries(modules[specifier]).map(([name, value]) => [name, typeof value === 'function' ? wrap(name, value) : value]));
    }
    return new vm.SyntheticModule(Object.keys(values), function () { for (const [name, value] of Object.entries(values)) this.setExport(name, value); }, { context });
  });
  await root.evaluate();
  all[packageName] = cases;
}
console.log(JSON.stringify(all));
