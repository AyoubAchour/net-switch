import assert from 'node:assert/strict';
import { test } from 'node:test';
import { AppInfo } from '../lib/appinfo.mjs';
import { appKey } from '../lib/apps.mjs';
import { InstalledApps } from '../lib/installed-apps.mjs';

const DISCORD = String.raw`C:\Users\Ayoub\AppData\Local\Discord`;
const dir = (name, directory = true) => ({ name, isDirectory: () => directory });
const missing = () => Object.assign(new Error('missing'), { code: 'ENOENT' });

test('Start menu apps are sorted, deduplicated by identity, and limited to existing executable apps', async () => {
  const shortcuts = [
    { name: 'Zebra', path: String.raw`C:\Zebra\zebra.exe` },
    { name: 'Discord', path: `${DISCORD}\\Update.exe`, args: '--processStart "Discord.exe"' },
    { name: 'Discord duplicate', path: `${DISCORD}\\app-1.0.9\\Discord.exe` },
    { name: 'Alpha', path: String.raw`C:\Alpha\ALPHA.EXE` },
    { name: 'Alpha duplicate', path: String.raw`c:\alpha\alpha.exe` },
    { name: 'Read me', path: String.raw`C:\Alpha\readme.txt` },
    { name: 'Missing', path: String.raw`C:\Missing\missing.exe` },
    { name: 'Directory', path: String.raw`C:\NotAFile.exe` },
    { name: 'Uninstall Alpha', path: String.raw`C:\Alpha\alpha.exe` },
    { name: 'Remove Beta', path: String.raw`C:\Beta\unins000.exe` },
    { name: 'Beta', path: String.raw`C:\Beta\BetaSetup.exe` },
    { name: 'Remove Gamma', path: String.raw`C:\Gamma\gamma.exe`, args: '--uninstall' },
    { name: 'Setup Delta', path: String.raw`C:\Delta\delta.exe` },
    { name: 'Updater', path: `${DISCORD}\\Update.exe` },
  ];
  const apps = new InstalledApps({
    readShortcuts: async (script, options) => {
      assert.equal(options.timeoutMs, 20_000);
      assert.match(script, /\$env:APPDATA/);
      assert.match(script, /\$env:ProgramData/);
      assert.match(script, /CreateShortcut/);
      return shortcuts;
    },
    readDirectory: async (folder) => {
      assert.equal(folder, DISCORD);
      return [dir('app-1.0.9'), dir('app-1.0.10'), dir('app-1.0.11'), dir('app-9.0.0', false), dir('app-2.0-beta')];
    },
    fileStat: async (file) => {
      if (file.includes('Missing') || file.includes('app-1.0.11')) throw missing();
      return { isFile: () => !file.includes('NotAFile') };
    },
  });
  assert.deepEqual(await apps.list(), [
    { name: 'Alpha', path: String.raw`C:\Alpha\ALPHA.EXE` },
    { name: 'Discord', path: `${DISCORD}\\app-1.0.10\\Discord.exe` },
    { name: 'Zebra', path: String.raw`C:\Zebra\zebra.exe` },
  ]);
});

test('Squirrel accepts unquoted targets and skips missing folders and unsafe target paths', async () => {
  const apps = new InstalledApps({
    readDirectory: async () => [dir('app-1.2.3')],
    fileStat: async () => ({ isFile: () => true }),
  });
  for (const args of ['--processStart Slack.exe', '--processStart=Slack.exe --process-start-args test']) {
    assert.equal(await apps.target({ path: `${DISCORD}\\Update.exe`, args }), `${DISCORD}\\app-1.2.3\\Slack.exe`);
  }
  for (const args of ['--processStart ..\\Slack.exe', '--processStart "C:\\Slack.exe"', '--processStart Slack.exe.bak']) {
    assert.equal(await apps.target({ path: `${DISCORD}\\Update.exe`, args }), null);
  }
  apps.readDirectory = async () => { throw missing(); };
  assert.equal(await apps.target({ path: `${DISCORD}\\Update.exe`, args: '--processStart Slack.exe' }), null);
});

test('concurrent requests share one scan and the five-minute cache, including empty menus', async () => {
  let now = 1000;
  let calls = 0;
  let release;
  const apps = new InstalledApps({ now: () => now, readShortcuts: () => {
    calls += 1;
    return new Promise((resolve) => { release = resolve; });
  } });
  const first = apps.list();
  const second = apps.list();
  assert.equal(calls, 1);
  release([]);
  assert.deepEqual(await first, []);
  await second;
  now += 5 * 60_000 - 1;
  await apps.list();
  assert.equal(calls, 1);
  now += 1;
  const refresh = apps.list();
  const concurrent = apps.list();
  assert.equal(calls, 2);
  release([]);
  await Promise.all([refresh, concurrent]);
});

test('scan failures keep their cause, do not become an empty cache, and can be retried', async () => {
  const failure = new Error('PowerShell did not answer within 20000 ms.');
  const apps = new InstalledApps({ readShortcuts: async () => { throw failure; } });
  await assert.rejects(apps.list(), (error) => error.cause === failure && /Start menu/.test(error.message));
  apps.readShortcuts = async () => [];
  assert.deepEqual(await apps.list(), []);
});

test('picker icons use AppInfo and refresh independently of the cached menu, even with routing off', async () => {
  const file = `${DISCORD}\\app-1.0.9165\\Discord.exe`;
  const appInfo = new AppInfo();
  let scans = 0;
  // Stand in for extraction; no PowerShell or disk writes in these tests.
  appInfo.lookupPending = async () => {
    for (const item of appInfo.pending) appInfo.cache.set(appKey(item), { name: 'Discord', icon: Buffer.from('png').toString('base64') });
    appInfo.pending.clear();
  };
  const apps = new InstalledApps({ appInfo,
    readShortcuts: async () => { scans += 1; return [{ name: 'Discord', path: file }]; },
    fileStat: async () => ({ isFile: () => true }),
  });
  assert.equal((await apps.list())[0].hasIcon, false);
  assert.equal((await apps.list())[0].hasIcon, true);
  assert.equal(scans, 1);
  assert.equal(appInfo.icon(file).toString(), 'png');
  assert.equal(appInfo.icon(appKey(file)).toString(), 'png');
  assert.equal(appInfo.icon(file.replace('9165', '9164')).toString(), 'png');
});

test('an icon lookup that failed on a deleted version is retried once for each new path', async () => {
  const oldPath = `${DISCORD}\\app-1.0.9164\\Discord.exe`;
  const newPath = oldPath.replace('9164', '9165');
  let calls = 0;
  const info = new AppInfo({ lookup: async () => { calls += 1; throw new Error('lookup failed'); } });
  info.describe(oldPath);
  await info.lookupPending();
  info.describe(oldPath);
  assert.equal(info.pending.size, 0, 'do not repeatedly retry the missing file');
  info.describe(newPath);
  assert.deepEqual([...info.pending], [newPath]);
  await info.lookupPending();
  info.describe(newPath);
  info.describe(oldPath);
  assert.equal(info.pending.size, 0, 'a failed retry also stays cached');
  assert.equal(calls, 2);
});
