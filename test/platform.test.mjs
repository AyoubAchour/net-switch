import assert from 'node:assert/strict';
import { readFile, mkdtemp, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { test } from 'node:test';
import { appPathPattern, normalizedAppPath } from '../lib/app-path.mjs';
import { buildEngineConfig, buildRuleSets, Engine } from '../lib/engine.mjs';
import { NetworkMonitor } from '../lib/helper.mjs';
import { findHelper } from '../lib/monitor.mjs';
import { platformFor } from '../lib/platform/index.mjs';
import { windows } from '../lib/platform/windows.mjs';
import { offerFrom, UpdateChecker } from '../lib/updates.mjs';

const platform = {
  ...windows,
  engineFileName: 'test-engine',
  helperFileName: 'test-helper',
  noAppPath: '/never/selected',
  requiredEngineFiles: () => ['test-library'],
  tunOptions: () => ({ mtu: 1500, iproute2_table_index: 3000 }),
  updateAssetName: (version, arch) => `test-${version}-${arch}.pkg`,
  appPath: {
    separator: '/', foldCase: (value) => value, regexFlags: '', versionPattern: '[0-9]+',
    versionFolder: (part) => /^rev[0-9]+$/.test(part) ? { before: 'rev', after: '', version: true } : null,
  },
};

test('only Windows can be selected until another platform is implemented', () => {
  assert.equal(platformFor('win32'), windows);
  for (const name of ['linux', 'darwin', 'freebsd']) {
    assert.throws(() => platformFor(name), { message: `Net Switch doesn't support ${name} yet` });
  }
  if (process.platform === 'win32') assert.equal(platformFor(), windows);
  else assert.throws(() => platformFor(), /doesn't support/);
});

test('path identity and engine rules use the supplied separator, case and version folders', () => {
  assert.equal(normalizedAppPath('/Apps/rev123/App', platform), '/Apps/rev*/App');
  assert.equal(appPathPattern('/Apps/rev123/App', platform), '^/Apps/rev[0-9]+/App$');
  const sets = buildRuleSets({
    platform, lines: [{ id: 'a' }, { id: 'b' }],
    appLines: { '/Apps/rev123/App': 'a', '/apps/rev124/App': 'a', '/Apps/rev125/App': 'b' },
  });
  assert.deepEqual(sets['apps-a'].rules, [{ process_path_regex: ['^/apps/rev[0-9]+/App$'] }]);
  assert.deepEqual(sets['apps-b'].rules, [{ process_path_regex: ['^/Apps/rev[0-9]+/App$'] }]);
  assert.deepEqual(sets['cut-b'].rules, [{ process_path: ['/never/selected'] }]);
});

test('TUN overrides do not change proxy mode, and helper lookup uses the platform filename', () => {
  const options = { platform, lines: [{ id: 'a', alias: 'test0' }], ruleDir: '', proxyPort: 1234 };
  const tun = buildEngineConfig({ ...options, mode: 'tun' }).inbounds[0];
  assert.equal(tun.mtu, 1500);
  assert.equal(tun.iproute2_table_index, 3000);
  assert.deepEqual(buildEngineConfig({ ...options, mode: 'proxy' }).inbounds[0], {
    type: 'mixed', tag: 'mixed-in', listen: '127.0.0.1', listen_port: 1234,
  });
  assert.equal(findHelper('/app', () => true, platform), path.join('/app', 'helper', 'test-helper'));
});

test('the platform supplies orphan handling, required libraries and fallback route reads', async () => {
  const dataDir = await mkdtemp(path.join(os.tmpdir(), 'netswitch-platform-'));
  try {
    const calls = [];
    const engine = new Engine({ dataDir, singBoxPath: path.join(dataDir, 'test-engine'), platform: {
      ...platform, stopOrphan: async (...args) => { calls.push(args); },
    } });
    await writeFile(engine.pidPath, '1234');
    await engine.stopOrphan();
    assert.deepEqual(calls, [[1234, engine.singBoxPath]]);
    await assert.rejects(readFile(engine.pidPath), { code: 'ENOENT' });
    await writeFile(path.join(dataDir, 'SHA256SUMS.txt'), `${'a'.repeat(64)}  test-engine\n`);
    await assert.rejects(engine.verifyEngineFiles('x64'), /no line for test-library/);
    const monitor = new NetworkMonitor({ platform: { ...platform, readDefaultRoutes: async () => ['test-route'] } });
    assert.deepEqual(await monitor.readDefaultRoutes(), ['test-route']);
  } finally {
    await rm(dataDir, { recursive: true, force: true });
  }
});

test('update checks select the supplied platform asset name', async () => {
  const name = 'test-1.2.3-x64.pkg';
  const release = {
    tag_name: 'v1.2.3', html_url: 'https://github.com/AyoubAchour/net-switch/releases/tag/v1.2.3',
    assets: [{ name, browser_download_url: `https://github.com/AyoubAchour/net-switch/releases/download/v1.2.3/${name}` }],
  };
  const offer = offerFrom(release, '0.3.1', 'x64', platform);
  assert.ok(offer.installer.endsWith(name));
  const checker = new UpdateChecker({
    currentVersion: '0.3.1', platform, architecture: () => 'x64',
    fetch: async () => ({ ok: true, json: async () => release }),
  });
  assert.equal(await checker.check(), 'available');
  assert.deepEqual(checker.offer, offer);
});
