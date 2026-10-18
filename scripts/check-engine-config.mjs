// Validation only: this never runs the engine or creates a TUN adapter.
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { buildEngineConfig, buildRuleSets } from '../lib/engine.mjs';
import { ruleCases } from '../test/windows-golden-cases.mjs';

const exe = path.resolve('engine/sing-box.exe');
const env = Object.fromEntries(Object.entries(process.env).filter(([key]) => !/^ENABLE_DEPRECATED_/i.test(key)));
const dir = await mkdtemp(path.join(tmpdir(), 'netswitch-config-check-'));
function run(args) {
  const result = spawnSync(exe, args, { env, encoding: 'utf8', windowsHide: true, timeout: 30_000 });
  const output = `${result.stdout ?? ''}${result.stderr ?? ''}`;
  assert.ifError(result.error);
  assert.equal(result.status, 0, `${args.join(' ')}\n${output}`);
  assert.doesNotMatch(output, /is deprecated in sing-box|ERROR|FATAL/, output);
  return output;
}
try {
  const version = run(['version']);
  console.log(version.trim());
  const tags = new Set(/^Tags:\s*(.*)$/mi.exec(version)?.[1].trim().split(/[\s,]+/));
  assert(tags.has('with_clash_api'), 'This engine lacks with_clash_api');
  let needsGvisor = false;
  let checked = 0;
  for (const { name, options } of ruleCases()) {
    // check validates these aliases without opening the corresponding adapters.
    for (const [tag, rules] of Object.entries(buildRuleSets(options))) {
      await writeFile(path.join(dir, `${tag}.json`), JSON.stringify(rules));
    }
    for (const mode of ['tun', 'proxy']) {
      for (const ipv6 of [false, true]) {
        const config = buildEngineConfig({ mode, ipv6, lines: options.lines,
          ruleDir: dir, apiPort: 12345, apiSecret: 'config-check', proxyPort: 12346 });
        needsGvisor ||= config.inbounds.some(({ type, stack }) => type === 'tun' && ['gvisor', 'mixed'].includes(stack));
        const file = path.join(dir, 'config.json');
        await writeFile(file, JSON.stringify(config));
        run(['check', '-c', file, '--disable-color']);
        console.log(`ok - ${name}, ${mode}, IPv6 ${ipv6}`);
        checked += 1;
      }
    }
  }
  assert.equal(tags.has('with_gvisor'), needsGvisor, 'with_gvisor must match the generated TUN stack requirement');
  console.log(`Checked ${checked} real configs, their rule files and required build tags without deprecated-feature overrides.`);
} finally {
  await rm(dir, { recursive: true, force: true });
}
