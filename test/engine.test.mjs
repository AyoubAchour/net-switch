import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdir, mkdtemp, readdir, readFile, rm, writeFile } from 'node:fs/promises';
import { createServer } from 'node:http';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { test } from 'node:test';
import {
  buildEngineConfig,
  buildRuleSets,
  Engine,
  appPathPattern,
  parseChecksums,
  PROBE_URLS,
  probeUrls,
  ruleSetTags,
} from '../lib/engine.mjs';
import { assignPorts } from '../lib/lines.mjs';

const LM = 'C:\\Users\\Admin\\AppData\\Local\\Programs\\LM Studio\\LM Studio.exe';
const DISCORD = 'C:\\Users\\Admin\\AppData\\Local\\Discord\\app-1.0\\Discord.exe';
const OTHER = 'C:\\Other\\app.exe';
const LM_RULE = { process_path_regex: [appPathPattern(LM)] };
const NEVER = { version: 3, rules: [{ process_path: ['C:\\NetSwitch\\no-app-selected.exe'] }] };

const CABLE = { id: 'a1', alias: 'Ethernet' };
const STICK = { id: 'b2', alias: 'Wi-Fi' };
const PHONE = { id: 'c3', alias: 'Ethernet 3' };
const LINES = [CABLE, STICK, PHONE];

test('an app’s rule matches its exact path in any letter case, and nothing else', () => {
  // Go's regular expressions read (?i) and these escapes the same way JavaScript does with the i flag.
  const pattern = new RegExp(appPathPattern(LM).replace('(?i)', ''), 'i');
  assert.ok(pattern.test(LM));
  assert.ok(pattern.test(LM.toLowerCase()));
  assert.ok(!pattern.test(`${LM}.bak`));
  assert.ok(!pattern.test(`D:${LM.slice(2)}`));
  assert.ok(!pattern.test(LM.replace('LM Studio.exe', 'LM StudioXexe')));
  assert.equal(appPathPattern('C:\\a (x86)\\b+c.exe'), '(?i)^C:\\\\a \\(x86\\)\\\\b\\+c\\.exe$');
});

test('every line gets a file of pinned apps; every line but the main one also gets a share file and a cut file', () => {
  assert.deepEqual(ruleSetTags(LINES), ['apps-a1', 'apps-b2', 'share-b2', 'cut-b2', 'apps-c3', 'share-c3', 'cut-c3']);
  const sets = buildRuleSets({ lines: LINES, appLines: { [LM]: 'b2' } });
  assert.deepEqual(Object.keys(sets), ruleSetTags(LINES));
  assert.deepEqual(sets['apps-b2'], { version: 3, rules: [LM_RULE] });
  // Files are never empty: sing-box refuses a rule set without rules.
  assert.deepEqual(sets['apps-a1'], NEVER);
  assert.deepEqual(sets['share-b2'], NEVER, 'no share without combining');
  assert.deepEqual(sets['cut-b2'], NEVER, 'nothing refused while the line has data');
  // A pin to a line that isn't there is left out.
  assert.deepEqual(buildRuleSets({ lines: [CABLE], appLines: { [LM]: 'zz' } })['apps-a1'], NEVER);
});

test('a line out of data with nowhere to send its apps refuses their new connections', () => {
  const sets = buildRuleSets({ lines: LINES, appLines: { [LM]: 'b2' }, blocked: ['b2'] });
  assert.deepEqual(sets['cut-b2'], { version: 3, rules: [LM_RULE] });
  assert.deepEqual(sets['cut-c3'], NEVER);
  const config = buildEngineConfig({ mode: 'tun', lines: LINES, apiPort: 1, apiSecret: 's', ruleDir: 'C:\\data' });
  // Refusals come before any app's route, so a refused app can't slip through.
  const cut = config.route.rules.findIndex((rule) => rule.rule_set === 'cut-b2');
  const apps = config.route.rules.findIndex((rule) => rule.rule_set === 'apps-b2');
  assert.ok(cut >= 0 && cut < apps);
  assert.equal(config.route.rules[cut].action, 'reject');
});

test('duplicate saved versions use the last pin in both routing rules and connection decisions', () => {
  const updated = DISCORD.replace('app-1.0', 'app-1.0.9165');
  const appLines = { [DISCORD]: 'a1', [updated]: 'b2' };
  const sets = buildRuleSets({ lines: LINES, appLines });
  assert.deepEqual(sets['apps-a1'], NEVER);
  assert.deepEqual(sets['apps-b2'].rules, [{ process_path_regex: [appPathPattern(updated)] }]);
  const engine = new Engine({ singBoxPath: 'unused.exe', dataDir: tmpdir(), mode: 'proxy' });
  engine.lines = LINES;
  engine.appLines = appLines;
  assert.equal(engine.routesTo({ metadata: { processPath: DISCORD } }), 'b2');
  assert.equal(engine.routesTo({ metadata: { processPath: updated } }), 'b2');
});

test('while combining, each line’s share file lists its share of ports 1024 to 65535', () => {
  const shares = { a1: 0.5, b2: 0.3, c3: 0.2 };
  const sets = buildRuleSets({ lines: LINES, combine: true, shares });
  const ports = assignPorts(shares);
  assert.deepEqual(sets['share-b2'].rules[0].source_port, ports.b2);
  assert.deepEqual(sets['share-c3'].rules[0].source_port, ports.c3);
  const total = 65535 - 1024 + 1;
  assert.ok(Math.abs(ports.b2.length / total - 0.3) < 0.001);
  assert.ok(Math.abs(ports.c3.length / total - 0.2) < 0.001);
  // A line without a share, such as one kept to its own apps, gets no ports.
  assert.deepEqual(buildRuleSets({ lines: LINES, combine: true, shares: { a1: 0.5, b2: 0.5 } })['share-c3'], NEVER);
});

// How sing-box routes a new connection with this config: the first rule
// whose rule set matches wins, else the final outbound. Rule sets match as
// sing-box reads them: every field of one rule must match.
function routeOf(config, sets, { processPath, sourcePort }) {
  const matches = (rule) => {
    const checks = [];
    if (rule.source_port) checks.push(rule.source_port.includes(sourcePort));
    if (rule.process_path) checks.push(rule.process_path.includes(processPath));
    if (rule.process_path_regex) {
      checks.push(rule.process_path_regex.some((pattern) => new RegExp(pattern.replace('(?i)', ''), 'i').test(processPath ?? '')));
    }
    return checks.every(Boolean);
  };
  for (const rule of config.route.rules) {
    if (!rule.rule_set) continue;
    if (sets[rule.rule_set].rules.some(matches)) return rule.outbound;
  }
  return config.route.final;
}

test('pinned apps win over sharing: an app pinned to the main line never shares, and one pinned elsewhere never leaves it', () => {
  const shares = { a1: 0.5, b2: 0.5 };
  const lines = [CABLE, STICK];
  const appLines = { [DISCORD]: 'a1', [LM]: 'b2' };
  const config = buildEngineConfig({ mode: 'tun', lines, apiPort: 1, apiSecret: 's', ruleDir: 'C:\\data' });
  const sets = buildRuleSets({ lines, appLines, combine: true, shares });
  const ports = assignPorts(shares);
  const stickPort = ports.b2[100];
  const cablePort = ports.a1[100];
  assert.equal(routeOf(config, sets, { processPath: DISCORD, sourcePort: stickPort }), 'lane-a1', 'kept on the main line');
  assert.equal(routeOf(config, sets, { processPath: DISCORD.toUpperCase(), sourcePort: stickPort }), 'lane-a1', 'in any letter case');
  assert.equal(routeOf(config, sets, { processPath: LM, sourcePort: cablePort }), 'lane-b2');
  assert.equal(routeOf(config, sets, { processPath: OTHER, sourcePort: stickPort }), 'lane-b2', 'everything else shares');
  assert.equal(routeOf(config, sets, { processPath: OTHER, sourcePort: cablePort }), 'lane-a1');
  // A program Windows couldn't name still shares.
  assert.equal(routeOf(config, sets, { processPath: undefined, sourcePort: stickPort }), 'lane-b2');
  // Ports below the shared range always use the main line.
  assert.equal(routeOf(config, sets, { processPath: OTHER, sourcePort: 80 }), 'lane-a1');
});

test('the engine’s own idea of where a connection goes matches the rule files it wrote', async () => {
  const dataDir = await mkdtemp(path.join(tmpdir(), 'net-switch-test-'));
  try {
    const engine = new Engine({ singBoxPath: 'sing-box.exe', dataDir, mode: 'proxy' });
    const appLines = { [DISCORD]: 'a1', [LM]: 'c3' };
    const shares = { a1: 0.4, b2: 0.35, c3: 0.25 };
    await engine.changeRules({ lines: LINES, appLines, combine: true, shares });
    const config = buildEngineConfig({ mode: 'tun', lines: LINES, apiPort: 1, apiSecret: 's', ruleDir: dataDir });
    const sets = buildRuleSets({ lines: LINES, appLines, combine: true, shares });
    for (const processPath of [DISCORD, DISCORD.replace('app-1.0', 'app-1.0.9165'), LM, OTHER]) {
      for (let port = 1000; port < 66000; port += 997) {
        const sourcePort = Math.min(port, 65535);
        const lane = routeOf(config, sets, { processPath, sourcePort });
        const lineId = engine.routesTo({ metadata: { processPath, sourcePort: String(sourcePort) } });
        assert.equal(`lane-${lineId}`, lane, `${processPath} from port ${sourcePort}`);
      }
    }
  } finally {
    await rm(dataDir, { recursive: true, force: true });
  }
});

test('the engine writes every rule file, keeps the other choices across a change, and removes files of lines that are gone', async () => {
  const dataDir = await mkdtemp(path.join(tmpdir(), 'net-switch-test-'));
  try {
    const engine = new Engine({ singBoxPath: 'sing-box.exe', dataDir, mode: 'proxy' });
    const written = async (tag) => JSON.parse(await readFile(path.join(dataDir, `${tag}.json`), 'utf8'));
    // The single file 0.2.0 used, left behind.
    await writeFile(path.join(dataDir, 'second-apps.json'), '{}');

    await engine.setLines(LINES);
    await engine.setAppLines({ [LM]: 'b2' });
    assert.deepEqual(await written('apps-b2'), { version: 3, rules: [LM_RULE] });

    await engine.setCombine(true);
    await engine.setShares({ a1: 0.5, b2: 0.5 });
    assert.equal((await written('share-b2')).rules[0].source_port.length, assignPorts({ a1: 0.5, b2: 0.5 }).b2.length);
    assert.deepEqual(await written('apps-b2'), { version: 3, rules: [LM_RULE] }, 'pinned apps kept');

    await engine.setCombine(false);
    assert.deepEqual(await written('share-b2'), NEVER);

    await engine.setLines([CABLE, STICK]);
    await engine.removeStaleRuleFiles();
    const names = (await readdir(dataDir)).filter((name) => name.endsWith('.json')).sort();
    assert.deepEqual(names, ['apps-a1.json', 'apps-b2.json', 'cut-b2.json', 'share-b2.json']);
  } finally {
    await rm(dataDir, { recursive: true, force: true });
  }
});

test('a change whose rule file could not be written never slips into the next change', async () => {
  const dataDir = await mkdtemp(path.join(tmpdir(), 'net-switch-test-'));
  try {
    const engine = new Engine({ singBoxPath: 'sing-box.exe', dataDir, mode: 'proxy' });
    await engine.setLines([CABLE, STICK]);
    const file = path.join(dataDir, 'apps-b2.json');
    await rm(file);
    // A folder where the file belongs makes every write fail.
    await mkdir(file);
    await assert.rejects(engine.setCombine(true));
    await assert.rejects(engine.setAppLines({ [LM]: 'b2' }));
    assert.equal(engine.combine, false);
    assert.deepEqual(engine.appLines, {});

    await rm(file, { recursive: true });
    await engine.setAppLines({});
    assert.deepEqual(JSON.parse(await readFile(file, 'utf8')), NEVER);
  } finally {
    await rm(dataDir, { recursive: true, force: true });
  }
});

test('when a later rule file can’t be written, the ones already written are put back', async () => {
  const dataDir = await mkdtemp(path.join(tmpdir(), 'net-switch-test-'));
  try {
    const engine = new Engine({ singBoxPath: 'sing-box.exe', dataDir, mode: 'proxy' });
    await engine.setLines([CABLE, STICK]);
    await engine.setAppLines({ [LM]: 'b2' });
    // Moving LM Studio to the main line writes apps-a1 first, then apps-b2.
    const later = path.join(dataDir, 'apps-b2.json');
    await rm(later);
    await mkdir(later);
    await assert.rejects(engine.setAppLines({ [LM]: 'a1' }));
    // apps-a1 is as before the change, so the engine doesn't send LM Studio to the main line.
    assert.deepEqual(JSON.parse(await readFile(path.join(dataDir, 'apps-a1.json'), 'utf8')), NEVER);
    assert.deepEqual(engine.appLines, { [LM]: 'b2' });
  } finally {
    await rm(dataDir, { recursive: true, force: true });
  }
});

test('with two lines or more, each line gets a selector that starts on itself, and everything else goes through the main line’s', () => {
  const config = buildEngineConfig({ mode: 'tun', lines: LINES, apiPort: 1, apiSecret: 's', ruleDir: 'C:\\data' });
  const byTag = new Map(config.outbounds.map((item) => [item.tag, item]));
  assert.deepEqual(byTag.get('line-b2'), { type: 'direct', tag: 'line-b2', bind_interface: 'Wi-Fi' });
  assert.deepEqual(byTag.get('lane-a1').outbounds, ['line-a1', 'line-b2', 'line-c3']);
  assert.deepEqual(byTag.get('lane-c3').outbounds, ['line-c3', 'line-a1', 'line-b2']);
  assert.equal(byTag.get('lane-c3').default, 'line-c3');
  assert.equal(config.route.final, 'lane-a1');
  // IPv6 is refused first, then pinned apps on every line, then the shares.
  assert.deepEqual(
    config.route.rules.map((rule) => rule.rule_set ?? rule.action),
    ['reject', 'cut-b2', 'cut-c3', 'apps-a1', 'apps-b2', 'apps-c3', 'share-b2', 'share-c3'],
  );
  assert.deepEqual(
    config.route.rule_set.map((set) => set.path),
    ruleSetTags(LINES).map((tag) => path.join('C:\\data', `${tag}.json`)),
  );
  // The engine's lines come to Net Switch, which keeps the log to a set size.
  assert.equal(config.log.output, undefined);

  // With IPv6 on every line, it is routed instead of refused.
  const withIpv6 = buildEngineConfig({ mode: 'tun', lines: LINES, apiPort: 1, apiSecret: 's', ruleDir: 'C:\\data', ipv6: true });
  assert.equal(withIpv6.route.rules.some((rule) => rule.ip_version === 6), false);

  const alone = buildEngineConfig({ mode: 'proxy', lines: [CABLE], apiPort: 1, apiSecret: 's', ruleDir: 'C:\\data' });
  assert.equal(alone.route.final, 'line-a1');
  assert.deepEqual(alone.outbounds.map((item) => item.tag), ['line-a1']);
  assert.deepEqual(alone.route.rules.map((rule) => rule.rule_set), ['apps-a1']);
});

// A stand-in for the engine's delay test: answers per test address.
async function fakeDelayApi(answers) {
  const asked = [];
  const server = createServer((request, response) => {
    const url = new URL(request.url, 'http://127.0.0.1');
    asked.push({ outbound: decodeURIComponent(url.pathname.split('/')[2]), url: url.searchParams.get('url') });
    const answer = answers[url.searchParams.get('url')] ?? 504;
    if (answer === 200) response.writeHead(200, { 'content-type': 'application/json' }).end(JSON.stringify({ delay: 40 }));
    else response.writeHead(answer).end();
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const engine = new Engine({ singBoxPath: 'sing-box.exe', dataDir: tmpdir(), mode: 'proxy' });
  engine.apiPort = server.address().port;
  engine.apiSecret = 'secret';
  return { engine, asked, stop: () => server.close() };
}

test('an internet test goes through the line’s own outbound and asks the second site only when the first fails, or both at once while in doubt', async () => {
  const [first, second] = PROBE_URLS;
  let api = await fakeDelayApi({ [first]: 200 });
  try {
    assert.equal(await api.engine.probe('b2'), 40);
    assert.deepEqual(api.asked, [{ outbound: 'line-b2', url: first }]);
  } finally {
    api.stop();
  }
  api = await fakeDelayApi({ [first]: 504, [second]: 200 });
  try {
    assert.equal(await api.engine.probe('b2'), 40);
    assert.deepEqual(api.asked.map((item) => item.url), [first, second]);
    api.asked.length = 0;
    assert.equal(await api.engine.probe('b2', { both: true }), 40);
    assert.deepEqual(api.asked.map((item) => item.url).sort(), [first, second].sort());
  } finally {
    api.stop();
  }
  // Both fail: a failed test. One failed and the engine didn't answer the other: nothing learned.
  api = await fakeDelayApi({ [first]: 503, [second]: 504 });
  try {
    assert.equal(await api.engine.probe('b2', { both: true }), false);
    assert.equal(await api.engine.probe('b2'), false);
  } finally {
    api.stop();
  }
  api = await fakeDelayApi({ [first]: 504, [second]: 500 });
  try {
    assert.equal(await api.engine.probe('b2', { both: true }), null);
    assert.equal(await api.engine.probe('b2'), null);
  } finally {
    api.stop();
  }
});

test('the person’s test addresses become HTTPS tests; the known ones keep their small pages', () => {
  assert.deepEqual(probeUrls(['1.1.1.1:443', '8.8.8.8:443']), PROBE_URLS);
  assert.deepEqual(probeUrls(['9.9.9.9:443', '149.112.112.112:8443']), ['https://9.9.9.9/', 'https://149.112.112.112:8443/']);
  assert.deepEqual(probeUrls([]), PROBE_URLS);
  assert.deepEqual(probeUrls(undefined), PROBE_URLS);
});

test('the checksum list is read line by line, and anything else in it is skipped', () => {
  const hash = 'a'.repeat(64);
  assert.deepEqual(parseChecksums(`# a comment\n${hash}  sing-box.exe\r\n${hash.toUpperCase()} *libcronet.dll\nnot a line\n`), [
    { hash, name: 'sing-box.exe' },
    { hash, name: 'libcronet.dll' },
  ]);
});


test('an engine file that doesn’t match its checksum is never run, and one that does is hashed only once', async () => {
  const dir = await mkdtemp(path.join(tmpdir(), 'net-switch-engine-'));
  try {
    const exe = path.join(dir, 'sing-box.exe');
    await writeFile(exe, 'the real engine');
    const good = createHash('sha256').update('the real engine').digest('hex');
    await writeFile(path.join(dir, 'libcronet.dll'), 'the real engine');
    await writeFile(path.join(dir, 'SHA256SUMS.txt'), `${good}  sing-box.exe\n${good}  libcronet.dll\n`);
    const engine = new Engine({ singBoxPath: exe, dataDir: dir, mode: 'proxy' });
    await engine.verifyEngineFiles();
    assert.equal(engine.verified.size, 2);

    await writeFile(exe, 'something else');
    await assert.rejects(engine.verifyEngineFiles(), /doesn’t match/);

    await rm(exe);
    await assert.rejects(engine.verifyEngineFiles(), /is missing/);

    // A list that doesn't name the engine would check nothing.
    await writeFile(path.join(dir, 'SHA256SUMS.txt'), `${good}  something-else.dll\n`);
    await assert.rejects(engine.verifyEngineFiles(), /has no line for sing-box\.exe/);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('ARM64 uses its checkout checksums or the installed list, and only ARM64 may omit Cronet', async () => {
  const dir = await mkdtemp(path.join(tmpdir(), 'net-switch-engine-arm64-'));
  try {
    const exe = path.join(dir, 'sing-box.exe');
    await writeFile(exe, 'arm64 engine');
    const good = createHash('sha256').update('arm64 engine').digest('hex');
    const armSums = `${good}  sing-box.exe\n`;
    await writeFile(path.join(dir, 'SHA256SUMS-arm64.txt'), armSums);
    await writeFile(path.join(dir, 'SHA256SUMS.txt'), `${'a'.repeat(64)}  sing-box.exe\n${good}  libcronet.dll\n`);
    const engine = new Engine({ singBoxPath: exe, dataDir: dir, mode: 'proxy', architecture: () => 'arm64' });
    // Source downloads match Windows, even when the current Node is x64.
    await engine.verifyEngineFiles();
    engine.verified.clear();
    await engine.verifyEngineFiles('arm64');
    engine.verified.clear();
    await assert.rejects(engine.verifyEngineFiles('x64'), /doesn’t match.*for x64/);
    await writeFile(path.join(dir, 'SHA256SUMS.txt'), armSums);
    await rm(path.join(dir, 'SHA256SUMS-arm64.txt'));
    // Installed copies use the bundled runtime's architecture, so an x64 copy
    // on ARM64 still requires Cronet until the native installer replaces it.
    if (process.arch === 'x64') await assert.rejects(engine.verifyEngineFiles(), /no line for libcronet/);
    await engine.verifyEngineFiles('arm64');
    await assert.rejects(engine.verifyEngineFiles('x64'), /no line for libcronet/);
    await writeFile(path.join(dir, 'SHA256SUMS.txt'), `${armSums}${good}  libcronet.dll\n`);
    await assert.rejects(engine.verifyEngineFiles('arm64'), /libcronet.dll is missing/);
    await rm(path.join(dir, 'SHA256SUMS.txt'));
    await assert.rejects(engine.verifyEngineFiles('arm64'), /SHA256SUMS.txt is missing/);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

// Validation-only change for PR #54 job gating (frozen 0.3.x suite case). Do not merge.
