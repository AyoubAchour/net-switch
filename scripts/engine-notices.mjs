// Read the actual linked modules, not every dependency of test-only tools.
// Prints the reproducible notices block. --check compares it with the reviewable
// block in THIRD_PARTY_NOTICES.md; a new compiled module requires a license review.
import { readFileSync, existsSync } from 'node:fs';
import { spawnSync } from 'node:child_process';

const args = process.argv.slice(2);
const check = args.includes('--check');
const binary = args.find(arg => arg !== '--check');
if (!binary) throw new Error('usage: node scripts/engine-notices.mjs <linux-engine-binary> [--check]');
const go = process.env.GO_BINARY || 'go';
const result = spawnSync(go, ['version', '-m', binary], { encoding: 'utf8' });
if (result.error || result.status !== 0) throw result.error || new Error(result.stderr);
const licenses = {
  'github.com/godbus/dbus/v5': ['BSD-2-Clause', 'vendor/github.com/godbus/dbus/v5/LICENSE'],
  'github.com/google/btree': ['Apache-2.0', 'vendor/github.com/google/btree/LICENSE'],
  'github.com/vishvananda/netlink': ['Apache-2.0', 'vendor/github.com/vishvananda/netlink/LICENSE'],
  'github.com/vishvananda/netns': ['Apache-2.0', 'vendor/github.com/vishvananda/netns/LICENSE'],
  'golang.org/x/exp': ['BSD-3-Clause', 'vendor/golang.org/x/exp/LICENSE'],
  'golang.org/x/net': ['BSD-3-Clause', 'vendor/golang.org/x/net/LICENSE'],
  'golang.org/x/sys': ['BSD-3-Clause', 'vendor/golang.org/x/sys/LICENSE'],
  'golang.org/x/time': ['BSD-3-Clause', 'vendor/golang.org/x/time/LICENSE'],
  'golang.zx2c4.com/wireguard': ['MIT', 'vendor/golang.zx2c4.com/wireguard/LICENSE'],
  'gvisor.dev/gvisor': ['Apache-2.0', 'third_party/gvisor/LICENSE'],
};
const lines = result.stdout.split(/\r?\n/);
const version = lines[0].match(/\bgo(\d+\.\d+\.\d+)\b/)?.[1];
if (!version) throw new Error('binary has no Go version');
const modules = lines.map(line => line.trim().split(/\s+/)).filter(parts => parts[0] === 'dep');
if (!modules.length) throw new Error('binary has no compiled module list');
const entries = modules.sort((a, b) => a[1].localeCompare(b[1], 'en')).map(([, name, version]) => {
  const notice = licenses[name];
  if (!notice) throw new Error(`unreviewed compiled dependency: ${name} ${version}`);
  const [license, file] = notice;
  if (!existsSync(file)) throw new Error(`missing license: ${file}`);
  return `- ${name} \`${version}\`, ${license}; license: \`${file}\`.`;
});
const generated = [
  '<!-- engine-modules:start -->',
  `Go ${version} runtime and standard library: BSD-3-Clause (the toolchain's LICENSE and PATENTS).`,
  '',
  ...entries,
  '<!-- engine-modules:end -->',
].join('\n');
if (check) {
  const text = readFileSync('THIRD_PARTY_NOTICES.md', 'utf8').replaceAll('\r\n', '\n');
  const recorded = text.match(/<!-- engine-modules:start -->[\s\S]*?<!-- engine-modules:end -->/)?.[0];
  if (recorded !== generated) {
    console.error('Compiled engine notices differ. Expected block:\n' + generated);
    process.exitCode = 1;
  } else console.log(`Compiled Linux engine notices match all ${modules.length} modules and Go ${version}.`);
} else console.log(generated);
