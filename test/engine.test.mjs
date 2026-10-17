import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { createServer } from 'node:http';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { test } from 'node:test';
import {
  buildEngineConfig,
  buildRuleSet,
  combinedSecondPorts,
  Engine,
  exactPathPattern,
  parseChecksums,
  portUsesSecond,
} from '../lib/engine.mjs';

const LM = 'C:\\Users\\Admin\\AppData\\Local\\Programs\\LM Studio\\LM Studio.exe';
const LM_RULE = { process_path_regex: [exactPathPattern(LM)] };
const PLACEHOLDER = 'C:\\NetSwitch\\no-app-selected.exe';

function secondCount(ports) {
  return ports.filter(portUsesSecond).length;
}

test('an app’s rule matches its exact path in any letter case, and nothing else', () => {
  // Go's regular expressions read (?i) and these escapes the same way JavaScript does with the i flag.
  const pattern = new RegExp(exactPathPattern(LM).replace('(?i)', ''), 'i');
  assert.ok(pattern.test(LM));
  assert.ok(pattern.test(LM.toLowerCase()));
  assert.ok(!pattern.test(`${LM}.bak`));
  assert.ok(!pattern.test(`D:${LM.slice(2)}`));
  assert.ok(!pattern.test(LM.replace('LM Studio.exe', 'LM StudioXexe')));
  assert.equal(exactPathPattern('C:\\a (x86)\\b+c.exe'), '(?i)^C:\\\\a \\(x86\\)\\\\b\\+c\\.exe$');
});

test('with combining off, the rule-set is the moved apps alone, or the placeholder', () => {
  assert.deepEqual(buildRuleSet([]), { version: 3, rules: [{ process_path: [PLACEHOLDER] }] });
  assert.deepEqual(buildRuleSet([LM], { combine: false }), { version: 3, rules: [LM_RULE] });
});

test('combining adds one rule that sends exactly half of ports 1024 to 65535 to the second connection', () => {
  const ruleSet = buildRuleSet([LM], { combine: true });
  assert.equal(ruleSet.rules.length, 2);
  assert.deepEqual(ruleSet.rules[0], LM_RULE);
  const ports = ruleSet.rules[1].source_port;
  assert.equal(ports.length, (65535 - 1024 + 1) / 2);
  assert.ok(ports.every((port, index) => Number.isInteger(port) && port >= 1024 && port <= 65535 && (index === 0 || port > ports[index - 1])));
  // An empty app list must still never match every app.
  assert.deepEqual(buildRuleSet([], { combine: true }).rules[0], { process_path: [PLACEHOLDER] });
  assert.equal(combinedSecondPorts(), ports);
});

const DISCORD = 'C:\\Users\\Admin\\AppData\\Local\\Discord\\app-1.0\\Discord.exe';

// How sing-box reads a headless rule: fields of one rule must all match,
// invert flips the whole rule, a logical "and" needs every inner rule.
function ruleMatches(rule, { processPath, sourcePort }) {
  let result;
  if (rule.type === 'logical') {
    result = rule.mode === 'and' ? rule.rules.every((inner) => ruleMatches(inner, { processPath, sourcePort })) : rule.rules.some((inner) => ruleMatches(inner, { processPath, sourcePort }));
  } else {
    const checks = [];
    if (rule.source_port) checks.push(rule.source_port.includes(sourcePort));
    if (rule.process_path) checks.push(rule.process_path.includes(processPath));
    if (rule.process_path_regex) {
      checks.push(rule.process_path_regex.some((pattern) => new RegExp(pattern.replace('(?i)', ''), 'i').test(processPath ?? '')));
    }
    result = checks.every(Boolean);
  }
  return rule.invert ? !result : result;
}

test('while combining, apps kept on the cable are left out of the second connection’s share', () => {
  const ruleSet = buildRuleSet([LM], { combine: true, cableAppPaths: [DISCORD] });
  assert.equal(ruleSet.rules.length, 2);
  assert.deepEqual(ruleSet.rules[0], LM_RULE);
  const [share, notKept] = ruleSet.rules[1].rules;
  assert.deepEqual(
    { type: ruleSet.rules[1].type, mode: ruleSet.rules[1].mode, ports: share.source_port, notKept },
    { type: 'logical', mode: 'and', ports: combinedSecondPorts(), notKept: { process_path_regex: [exactPathPattern(DISCORD)], invert: true } },
  );

  const secondPort = combinedSecondPorts()[100];
  const cablePort = Array.from({ length: 200 }, (_, index) => 50000 + index).find((port) => !portUsesSecond(port));
  const toSecond = (processPath, sourcePort) => ruleSet.rules.some((rule) => ruleMatches(rule, { processPath, sourcePort }));
  assert.equal(toSecond(DISCORD, secondPort), false, 'kept on the cable');
  assert.equal(toSecond(DISCORD.toUpperCase(), secondPort), false, 'in any letter case');
  assert.equal(toSecond('C:\\Other\\app.exe', secondPort), true, 'everything else still shares');
  assert.equal(toSecond('C:\\Other\\app.exe', cablePort), false);
  assert.equal(toSecond(LM, 1), true, 'moved apps use the second connection');
  // A program Windows couldn't name still shares both lines.
  assert.equal(toSecond(undefined, secondPort), true);
});

test('apps kept on the cable change nothing without combining, and an empty list adds no rule sing-box would refuse', () => {
  assert.deepEqual(buildRuleSet([LM], { combine: false, cableAppPaths: [DISCORD] }), { version: 3, rules: [LM_RULE] });
  assert.deepEqual(buildRuleSet([LM], { combine: true, cableAppPaths: [] }).rules[1], { source_port: combinedSecondPorts() });
});

test('the ports Windows handed out on this PC split four and four', () => {
  // Eight connections through the TUN, each followed by the engine's own socket.
  const throughTun = [64393, 64395, 64397, 64399, 64401, 64403, 64405, 64407];
  // Eight parallel downloads through the test-mode proxy.
  const throughProxy = [49673, 49674, 49675, 49676, 49677, 49678, 49680, 49681];
  assert.equal(secondCount(throughTun), 4);
  assert.equal(secondCount(throughProxy), 4);
});

test('any eight connections one or two ports apart split at worst five and three', () => {
  for (let start = 1024; start + 14 <= 65535; start += 1) {
    for (const step of [1, 2]) {
      const ports = Array.from({ length: 8 }, (_, index) => start + index * step);
      const count = secondCount(ports);
      assert.ok(count >= 3 && count <= 5, `step ${step} from ${start}: ${count} of 8 on the second connection`);
    }
  }
});

test('wider steps rarely put a whole burst on one line', () => {
  let oneLine = 0;
  let bursts = 0;
  for (let start = 1024; start + 28 <= 65535; start += 1) {
    const count = secondCount(Array.from({ length: 8 }, (_, index) => start + index * 4));
    if (count === 0 || count === 8) oneLine += 1;
    bursts += 1;
  }
  // A fair coin per block puts all eight on one line 2 times in 256.
  assert.ok(oneLine / bursts < 0.02, `${oneLine} of ${bursts} bursts landed on one line`);
});

test('the engine writes moved apps and combining together, and keeps both across changes', async () => {
  const dataDir = await mkdtemp(path.join(tmpdir(), 'net-switch-test-'));
  try {
    const engine = new Engine({ singBoxPath: 'sing-box.exe', dataDir, mode: 'proxy' });
    const written = async () => JSON.parse(await readFile(path.join(dataDir, 'second-apps.json'), 'utf8'));

    await engine.setSecondApps([LM]);
    assert.deepEqual(await written(), { version: 3, rules: [LM_RULE] });

    await engine.setCombine(true);
    let ruleSet = await written();
    assert.deepEqual(ruleSet.rules[0], LM_RULE);
    assert.equal(ruleSet.rules[1].source_port.length, 32256);

    await engine.setSecondApps([]);
    ruleSet = await written();
    assert.deepEqual(ruleSet.rules[0], { process_path: [PLACEHOLDER] });
    assert.equal(ruleSet.rules.length, 2);

    await engine.setCombine(false);
    assert.deepEqual(await written(), { version: 3, rules: [{ process_path: [PLACEHOLDER] }] });
  } finally {
    await rm(dataDir, { recursive: true, force: true });
  }
});

test('moved apps and apps kept on the cable are written in one change, and kept when combining changes', async () => {
  const dataDir = await mkdtemp(path.join(tmpdir(), 'net-switch-test-'));
  try {
    const engine = new Engine({ singBoxPath: 'sing-box.exe', dataDir, mode: 'proxy' });
    const written = async () => JSON.parse(await readFile(path.join(dataDir, 'second-apps.json'), 'utf8'));

    await engine.setCombine(true);
    await engine.setAppLanes([LM], [DISCORD]);
    assert.deepEqual([engine.secondAppPaths, engine.cableAppPaths], [[LM], [DISCORD]]);
    let ruleSet = await written();
    assert.deepEqual(ruleSet.rules[0], LM_RULE);
    assert.equal(ruleSet.rules[1].type, 'logical');

    // Moving the second connection's apps alone keeps the cable's list.
    await engine.setSecondApps([]);
    ruleSet = await written();
    assert.deepEqual(ruleSet.rules[1].rules[1], { process_path_regex: [exactPathPattern(DISCORD)], invert: true });

    await engine.setCombine(false);
    assert.deepEqual(await written(), { version: 3, rules: [{ process_path: [PLACEHOLDER] }] });
    await engine.setCombine(true);
    assert.equal((await written()).rules[1].type, 'logical');
  } finally {
    await rm(dataDir, { recursive: true, force: true });
  }
});

test('a change whose rule file could not be written never slips into the next change', async () => {
  const dataDir = await mkdtemp(path.join(tmpdir(), 'net-switch-test-'));
  try {
    const engine = new Engine({ singBoxPath: 'sing-box.exe', dataDir, mode: 'proxy' });
    const file = path.join(dataDir, 'second-apps.json');
    // A folder where the file belongs makes every write fail.
    await mkdir(file);
    await assert.rejects(engine.setCombine(true));
    await assert.rejects(engine.setSecondApps([LM]));
    assert.equal(engine.combine, false);
    assert.deepEqual(engine.secondAppPaths, []);

    await rm(file, { recursive: true });
    await engine.setSecondApps([]);
    assert.deepEqual(JSON.parse(await readFile(file, 'utf8')), { version: 3, rules: [{ process_path: [PLACEHOLDER] }] });
  } finally {
    await rm(dataDir, { recursive: true, force: true });
  }
});

// A stand-in for the engine's control API: it lists connections and accepts DELETE.
async function fakeEngineApi(connections, { answers = {}, delayMs = 0, listDelayMs = 0, secondApps = [LM], cableApps = [], combine = false } = {}) {
  const deleted = [];
  const server = createServer((request, response) => {
    if (request.headers.authorization !== 'Bearer secret') {
      response.writeHead(401).end();
      return;
    }
    if (request.method === 'GET' && request.url === '/connections') {
      setTimeout(() => response.writeHead(200, { 'content-type': 'application/json' }).end(JSON.stringify({ connections })), listDelayMs);
      return;
    }
    const match = /^\/connections\/(.+)$/.exec(request.url);
    if (request.method === 'DELETE' && match) {
      const id = decodeURIComponent(match[1]);
      setTimeout(() => {
        deleted.push(id);
        response.writeHead(answers[id] ?? 200).end();
      }, delayMs);
      return;
    }
    response.writeHead(404).end();
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const engine = new Engine({ singBoxPath: 'sing-box.exe', dataDir: tmpdir(), mode: 'proxy' });
  engine.apiPort = server.address().port;
  engine.apiSecret = 'secret';
  // The rules the engine has now decide which stuck connections still belong on the second connection.
  engine.secondAppPaths = secondApps;
  engine.cableAppPaths = cableApps;
  engine.combine = combine;
  const stop = () => {
    server.closeAllConnections?.();
    server.close();
  };
  return { engine, deleted, stop };
}

const via = (id, ...chains) => ({ id, chains, metadata: { processPath: LM, sourcePort: '50001' } });

test('when the second connection is back, only the connections stuck on the cable are closed', async () => {
  const { engine, deleted, stop } = await fakeEngineApi([
    via('stuck-1', 'cable', 'second-lane'),
    via('on-second', 'second', 'second-lane'),
    via('plain cable', 'cable'),
    via('stuck/2', 'cable', 'second-lane'),
    via('cable app on the second connection', 'second', 'main-lane'),
  ]);
  try {
    assert.deepEqual(await engine.releaseFallbackConnections(), { found: 2, closed: 2, failed: 0, interrupted: false });
    assert.deepEqual(deleted.sort(), ['stuck-1', 'stuck/2']);
  } finally {
    stop();
  }
});

test('with nothing stuck on the cable, nothing is closed', async () => {
  const { engine, deleted, stop } = await fakeEngineApi([via('a', 'second', 'second-lane'), via('b', 'cable')]);
  try {
    assert.deepEqual(await engine.releaseFallbackConnections(), { found: 0, closed: 0, failed: 0, interrupted: false });
    assert.deepEqual(deleted, []);
  } finally {
    stop();
  }
});

test('a connection that already ended counts as closed, one the engine refuses counts as failed', async () => {
  const { engine, stop } = await fakeEngineApi(
    [via('gone', 'cable', 'second-lane'), via('refused', 'cable', 'second-lane'), via('fine', 'cable', 'second-lane')],
    { answers: { gone: 404, refused: 500 } },
  );
  try {
    assert.deepEqual(await engine.releaseFallbackConnections(), { found: 3, closed: 2, failed: 1, interrupted: false });
  } finally {
    stop();
  }
});

test('closing stops when the time budget is used up, and the rest count as not closed', async () => {
  const stuck = Array.from({ length: 5 }, (_, index) => via(`s${index}`, 'cable', 'second-lane'));
  // Wide margins: with an 80 ms close and a 100 ms budget, a busy machine could
  // spend the whole budget listing the connections, and then close none.
  const { engine, stop } = await fakeEngineApi(stuck, { delayMs: 300 });
  try {
    const result = await engine.releaseFallbackConnections({ budgetMs: 450 });
    assert.equal(result.found, 5);
    assert.equal(result.closed + result.failed, 5);
    assert.ok(result.closed >= 1 && result.failed >= 1, JSON.stringify(result));
  } finally {
    stop();
  }
});

test('when the cable is back, only the cable’s connections stuck on the second connection are closed', async () => {
  const CHROME = 'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe';
  const stuck = (id, processPath, chains) => ({ id, chains, metadata: { processPath, sourcePort: '50001' } });
  const { engine, deleted, stop } = await fakeEngineApi(
    [
      stuck('chrome-stuck', CHROME, ['second', 'main-lane']),
      stuck('chrome-home', CHROME, ['cable', 'main-lane']),
      // LM Studio is moved to the second connection: it belongs there.
      stuck('lm-on-second', LM, ['second', 'main-lane']),
      stuck('lm-stuck-on-cable', LM, ['cable', 'second-lane']),
    ],
    { secondApps: [LM] },
  );
  try {
    assert.deepEqual(await engine.releaseFallbackConnections({ lane: 'main' }), { found: 1, closed: 1, failed: 0, interrupted: false });
    assert.deepEqual(deleted, ['chrome-stuck']);
  } finally {
    stop();
  }
});

test('a connection the rules no longer send to the second connection stays where it is', async () => {
  const CHROME = 'C:\Program Files\Google\Chrome\Application\chrome.exe';
  const secondPort = Array.from({ length: 200 }, (_, index) => 50000 + index).find(portUsesSecond);
  const cablePort = Array.from({ length: 200 }, (_, index) => 50000 + index).find((port) => !portUsesSecond(port));
  const stuck = (id, processPath, sourcePort) => ({ id, chains: ['cable', 'second-lane'], metadata: { processPath, sourcePort: String(sourcePort) } });
  const connections = [
    stuck('moved-app', LM, cablePort),
    stuck('combined-second', CHROME, secondPort),
    stuck('combined-cable', CHROME, cablePort),
  ];

  // The person moved LM Studio to the cable and stopped combining during the drop.
  let api = await fakeEngineApi(connections, { secondApps: [], combine: false });
  try {
    assert.deepEqual(await api.engine.releaseFallbackConnections(), { found: 0, closed: 0, failed: 0, interrupted: false });
    assert.deepEqual(api.deleted, []);
  } finally {
    api.stop();
  }

  // LM Studio is still moved; combining is still on: Chrome's share on the second connection returns too.
  api = await fakeEngineApi(connections, { secondApps: [LM], combine: true });
  try {
    assert.deepEqual(await api.engine.releaseFallbackConnections(), { found: 2, closed: 2, failed: 0, interrupted: false });
    assert.deepEqual(api.deleted.sort(), ['combined-second', 'moved-app']);
  } finally {
    api.stop();
  }
});

test('when lines come back while combining, an app kept on the cable gets back all its connections', async () => {
  const secondPort = Array.from({ length: 200 }, (_, index) => 50000 + index).find(portUsesSecond);
  const stuck = (id, processPath, chains) => ({ id, chains, metadata: { processPath, sourcePort: String(secondPort) } });
  const OTHER = 'C:\\Other\\app.exe';
  const connections = [
    // The cable dropped: Discord's connection fell back to the second connection.
    stuck('kept-on-second', DISCORD, ['second', 'main-lane']),
    // The second connection dropped: this one, in the share, fell back to the cable.
    stuck('kept-share-on-cable', DISCORD, ['cable', 'second-lane']),
    stuck('other-share-on-cable', OTHER, ['cable', 'second-lane']),
  ];
  let api = await fakeEngineApi(connections, { secondApps: [], cableApps: [DISCORD], combine: true });
  try {
    // Cable back: Discord's connection on the second connection is out of place.
    assert.deepEqual(await api.engine.releaseFallbackConnections({ lane: 'main' }), { found: 1, closed: 1, failed: 0, interrupted: false });
    assert.deepEqual(api.deleted, ['kept-on-second']);
  } finally {
    api.stop();
  }
  api = await fakeEngineApi(connections, { secondApps: [], cableApps: [DISCORD], combine: true });
  try {
    // Second connection back: only the sharing app's connection returns to it.
    assert.deepEqual(await api.engine.releaseFallbackConnections(), { found: 1, closed: 1, failed: 0, interrupted: false });
    assert.deepEqual(api.deleted, ['other-share-on-cable']);
  } finally {
    api.stop();
  }
});

// A stand-in for the engine's delay test: answers per test address.
async function fakeDelayApi(answers) {
  const asked = [];
  const server = createServer((request, response) => {
    const url = new URL(request.url, 'http://127.0.0.1');
    const target = url.searchParams.get('url');
    asked.push(target);
    const answer = answers[target] ?? 504;
    if (answer === 200) response.writeHead(200, { 'content-type': 'application/json' }).end(JSON.stringify({ delay: 40 }));
    else response.writeHead(answer).end();
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const engine = new Engine({ singBoxPath: 'sing-box.exe', dataDir: tmpdir(), mode: 'proxy' });
  engine.apiPort = server.address().port;
  engine.apiSecret = 'secret';
  return { engine, asked, stop: () => server.close() };
}

test('an internet test asks the second site only when the first fails, or both at once while in doubt', async () => {
  const [first, second] = ['https://1.1.1.1/cdn-cgi/trace', 'https://8.8.8.8/'];
  let api = await fakeDelayApi({ [first]: 200 });
  try {
    assert.equal(await api.engine.probe('second'), 40);
    assert.deepEqual(api.asked, [first]);
  } finally {
    api.stop();
  }
  api = await fakeDelayApi({ [first]: 504, [second]: 200 });
  try {
    assert.equal(await api.engine.probe('second'), 40);
    assert.deepEqual(api.asked, [first, second]);
    api.asked.length = 0;
    assert.equal(await api.engine.probe('second', { both: true }), 40);
    assert.deepEqual(api.asked.sort(), [first, second].sort());
  } finally {
    api.stop();
  }
  // Both fail: a failed test. One failed and the engine didn't answer the other: nothing learned.
  api = await fakeDelayApi({ [first]: 503, [second]: 504 });
  try {
    assert.equal(await api.engine.probe('second', { both: true }), false);
    assert.equal(await api.engine.probe('second'), false);
  } finally {
    api.stop();
  }
  api = await fakeDelayApi({ [first]: 504, [second]: 500 });
  try {
    assert.equal(await api.engine.probe('second', { both: true }), null);
    assert.equal(await api.engine.probe('second'), null);
  } finally {
    api.stop();
  }
});

test('closing stops as soon as the second connection drops again', async () => {
  const stuck = Array.from({ length: 4 }, (_, index) => via(`s${index}`, 'cable', 'second-lane'));
  const { engine, deleted, stop } = await fakeEngineApi(stuck);
  try {
    let asked = 0;
    const result = await engine.releaseFallbackConnections({ shouldContinue: () => (asked += 1) <= 2 });
    assert.deepEqual(result, { found: 4, closed: 2, failed: 0, interrupted: true });
    assert.equal(deleted.length, 2);
  } finally {
    stop();
  }
});

test('the time budget counts from the start, so a slow list leaves no time to close', async () => {
  const stuck = Array.from({ length: 3 }, (_, index) => via(`s${index}`, 'cable', 'second-lane'));
  const { engine, deleted, stop } = await fakeEngineApi(stuck, { listDelayMs: 150 });
  try {
    assert.deepEqual(await engine.releaseFallbackConnections({ budgetMs: 100 }), { found: 3, closed: 0, failed: 3, interrupted: false });
    assert.deepEqual(deleted, []);
  } finally {
    stop();
  }
});

test('a program path matches its rule in any letter case, as the rule itself does in sing-box', async () => {
  const lower = LM.toLowerCase();
  const stuck = { id: 'other-case', chains: ['cable', 'second-lane'], metadata: { processPath: lower, sourcePort: '50001' } };
  const { engine, deleted, stop } = await fakeEngineApi([stuck], { secondApps: [LM], combine: false });
  try {
    assert.deepEqual(await engine.releaseFallbackConnections(), { found: 1, closed: 1, failed: 0, interrupted: false });
    assert.deepEqual(deleted, ['other-case']);
  } finally {
    stop();
  }
});

test('with a second connection, both lanes get a selector and everything else goes through the cable’s', () => {
  const config = buildEngineConfig({ mode: 'tun', mainAlias: 'Ethernet', secondAlias: 'Wi-Fi', apiPort: 1, apiSecret: 's', ruleSetPath: 'r.json' });
  const byTag = new Map(config.outbounds.map((item) => [item.tag, item]));
  assert.deepEqual(byTag.get('second-lane').outbounds, ['second', 'cable']);
  assert.deepEqual(byTag.get('main-lane').outbounds, ['cable', 'second']);
  assert.equal(byTag.get('main-lane').default, 'cable');
  assert.equal(config.route.final, 'main-lane');
  // The engine's lines come to Net Switch, which keeps the log to a set size.
  assert.equal(config.log.output, undefined);

  const alone = buildEngineConfig({ mode: 'tun', mainAlias: 'Ethernet', secondAlias: null, apiPort: 1, apiSecret: 's', ruleSetPath: 'r.json' });
  assert.equal(alone.route.final, 'cable');
  assert.deepEqual(alone.outbounds.map((item) => item.tag), ['cable']);
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
