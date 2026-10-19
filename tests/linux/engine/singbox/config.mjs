// Writes sing-box's config and rule files for the Linux acceptance suite, with
// Net Switch's own generator (lib/engine.mjs), so the baseline is configured
// exactly as today's app configures its engine. The spec comes as JSON on
// standard input:
//
//   { out, rulesOnly, profile: "linux" | "product", lines: [{ id, alias }],
//     appLines: { path: lineId }, combine, shares: { lineId: share },
//     blocked: [lineId], ipv6, apiPort, secret, tableIndex, ruleIndex,
//     excludeInterfaces: [name], logLevel }
//
// Profile "product" is buildEngineConfig's output as is. Profile "linux" adds
// what the feasibility spike found Linux needs (LINUX-PLAN.md section 0):
//   - no route_exclude_address: it resets connections opened before start and
//     breaks the main line under rp_filter=1. Local ranges are kept out by the
//     driver's own "to <range> lookup main" rules instead;
//   - our own iproute2 table and rule indexes, so another sing-box or mihomo
//     tool's stop can't delete our rules;
//   - container bridges in exclude_interface;
//   - app rules that still match after the program file is replaced while it
//     runs (the kernel then reports "<path> (deleted)").
// auto_redirect stays off in both: after a crash it leaves an nftables table
// that breaks all new TCP.
import { readFileSync, renameSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { buildEngineConfig, buildRuleSets } from '../../../../lib/engine.mjs';

// How Linux program paths become rules: '/'-separated and case-sensitive.
// Snap revisions (/snap/<name>/<revision>/...) and AppImage mount folders
// (/tmp/.mount_<Name><6 random characters>/...) change between runs, so they
// match any value. There is no Linux platform in lib/platform yet; this
// follows LINUX-PLAN.md section 2.2.
const linuxAppPath = {
  separator: '/',
  foldCase: (value) => value,
  regexFlags: '',
  versionPattern: '[^/]+',
  versionFolder(segment) {
    if (/^[0-9]+$/.test(segment)) return { before: '', after: '', version: true };
    const mount = /^(\.mount_.+?)[A-Za-z0-9]{6}$/.exec(segment);
    if (mount) return { before: mount[1], after: '', version: true };
    return null;
  },
};
const linux = {
  noAppPath: '/nonexistent/netswitch/no-app-selected',
  appPath: linuxAppPath,
  tunOptions: () => ({}),
};

const spec = JSON.parse(readFileSync(0, 'utf8'));
const out = path.resolve(spec.out);
const written = [];
const write = (name, value, compact = false) => {
  const file = path.join(out, name);
  // Like the app's writeFileAtomic: the engine reloads a rule file when it
  // changes and must never read half of one.
  writeFileSync(`${file}.tmp`, JSON.stringify(value, null, compact ? undefined : 2));
  renameSync(`${file}.tmp`, file);
  written.push(name);
};

const sets = buildRuleSets({
  lines: spec.lines,
  appLines: spec.appLines ?? {},
  combine: Boolean(spec.combine),
  shares: spec.shares ?? {},
  blocked: spec.blocked ?? [],
  platform: linux,
});
if (spec.profile === 'linux') {
  // A blocked line's cut- set shares its rule object with its apps- set.
  const done = new WeakSet();
  for (const [tag, set] of Object.entries(sets)) {
    if (!tag.startsWith('apps-') && !tag.startsWith('cut-')) continue;
    for (const rule of set.rules) {
      if (!rule.process_path_regex || done.has(rule)) continue;
      done.add(rule);
      rule.process_path_regex = rule.process_path_regex.map((re) => re.replace(/\$$/, '( \\(deleted\\))?$'));
    }
  }
}
for (const [tag, set] of Object.entries(sets)) write(`${tag}.json`, set, tag.startsWith('share-'));

if (!spec.rulesOnly) {
  const config = buildEngineConfig({
    mode: 'tun',
    lines: spec.lines,
    apiPort: spec.apiPort,
    apiSecret: spec.secret,
    proxyPort: null,
    ruleDir: out,
    ipv6: Boolean(spec.ipv6),
    platform: linux,
  });
  config.log.level = spec.logLevel ?? config.log.level;
  if (spec.profile === 'linux') {
    const tun = config.inbounds[0];
    delete tun.route_exclude_address;
    tun.iproute2_table_index = spec.tableIndex;
    tun.iproute2_rule_index = spec.ruleIndex;
    if (spec.excludeInterfaces?.length) tun.exclude_interface = spec.excludeInterfaces;
  }
  write('config.json', config);
}
process.stdout.write(`${JSON.stringify({ written })}\n`);
