// Writes a sing-box config and its rule files for the Linux spike. TUN configs
// come from Net Switch's own generator (lib/engine.mjs buildEngineConfig), then
// get the Linux changes the plan lists: our own iproute2 indexes, a stack, and
// optionally auto_redirect and excluded interfaces. Rule files follow
// buildRuleSets' shape, with Linux paths: '/'-separated and case-sensitive.
//
//   node config.mjs --out DIR [--stack gvisor|system|mixed] [--auto-redirect]
//     [--exclude if1,if2] [--no-rules] [--share-b 0.3333] [--extra-rule JSON]
//     [--log-level warn]
//   node config.mjs --out DIR --identity
import { mkdirSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { buildEngineConfig } from '../../lib/engine.mjs';
import { assignPorts } from '../../lib/lines.mjs';

const args = process.argv.slice(2);
const option = (name, fallback) => {
  const index = args.indexOf(name);
  return index >= 0 ? args[index + 1] : fallback;
};
const flag = (name) => args.includes(name);
const out = path.resolve(option('--out'));
mkdirSync(out, { recursive: true });
const write = (name, value) => writeFileSync(path.join(out, name), JSON.stringify(value, null, name.startsWith('share-') ? undefined : 2));

export const API = '127.0.0.1:9090';
export const SECRET = 'spike';
// Not 2022/9000, so stopping another sing-box or mihomo tool can't wipe ours.
const TABLE_INDEX = Number(option('--table', '3110'));
const RULE_INDEX = Number(option('--rule-index', '31100'));
// A rule file is never empty; this program never exists.
const NEVER = { process_path: ['/nonexistent/netswitch/no-app-selected'] };
const exact = (file) => `^${file.replace(/[\\^$.*+?()[\]{}|]/g, '\\$&')}$`;

if (flag('--identity')) {
  // Root namespace, no TUN: a local proxy whose connections are matched by
  // process like the TUN's, so snap and Flatpak apps can be tried as they are.
  const rules = [
    { process_path_regex: [exact('/opt/nsapps/delta/node'), exact('/opt/nsapps/epsilon/node')], outbound: 'strict' },
    { process_path_regex: ['^/opt/nsapps/zeta/node( \\(deleted\\))?$'], outbound: 'tolerant' },
    { process_path_regex: ['^/usr/bin/python3(\\.[0-9]+)?$'], outbound: 'python' },
    { process_path_regex: ['^/snap/'], outbound: 'snap' },
    { process_path_regex: ['^/tmp/\\.mount_', '^/tmp/appimage_extracted_'], outbound: 'appimage' },
    { process_path_regex: ['^/app/', '^/usr/bin/curl$'], outbound: 'usr-or-app' },
    { process_path_regex: ['^/opt/nsapps/alpha/'], outbound: 'alpha' },
  ].map((rule) => ({ ...rule, action: 'route' }));
  const tags = [...new Set(rules.map((rule) => rule.outbound)), 'other'];
  write('config.json', {
    log: { level: option('--log-level', 'warn'), timestamp: true },
    inbounds: [{ type: 'mixed', tag: 'mixed-in', listen: '127.0.0.1', listen_port: 2080 }],
    outbounds: tags.map((tag) => ({ type: 'direct', tag })),
    route: { rules, final: 'other', find_process: true },
    experimental: { clash_api: { external_controller: '127.0.0.1:9091', secret: SECRET } },
  });
  process.exit(0);
}

const lines = [
  { id: 'aa', alias: 'vethA' },
  { id: 'bb', alias: 'vethB' },
];
const config = buildEngineConfig({ mode: 'tun', lines, apiPort: 9090, apiSecret: SECRET, proxyPort: null, ruleDir: out });
config.log.level = option('--log-level', 'warn');
const tun = config.inbounds[0];
tun.stack = option('--stack', 'gvisor');
tun.iproute2_table_index = TABLE_INDEX;
tun.iproute2_rule_index = RULE_INDEX;
if (flag('--auto-redirect')) tun.auto_redirect = true;
const exclude = option('--exclude');
if (exclude) tun.exclude_interface = exclude.split(',');

if (flag('--no-rules')) {
  // Process lookup fully off: no rule may name a process, including the
  // placeholder, or sing-box looks processes up anyway.
  config.route.rules = config.route.rules.filter((rule) => !rule.rule_set);
  delete config.route.rule_set;
  config.route.find_process = false;
} else {
  // bravo's copies are placed on line B; alpha is left unplaced (main line A).
  const bravo = [exact('/opt/nsapps/bravo/curl'), exact('/opt/nsapps/bravo/node')];
  const shareB = option('--share-b');
  const ports = shareB ? assignPorts({ aa: 1 - Number(shareB), bb: Number(shareB) }) : {};
  write('apps-aa.json', { version: 3, rules: [NEVER] });
  write('apps-bb.json', { version: 3, rules: [{ process_path_regex: bravo }] });
  write('share-bb.json', { version: 3, rules: [ports.bb?.length ? { source_port: ports.bb } : NEVER] });
  write('cut-bb.json', { version: 3, rules: [NEVER] });
}
const extra = option('--extra-rule');
if (extra) config.route.rules.splice(1, 0, JSON.parse(extra));
write('config.json', config);
