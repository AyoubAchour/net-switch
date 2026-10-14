import assert from 'node:assert/strict';
import { mkdir, mkdtemp, readFile, readdir, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { test } from 'node:test';
import { Settings } from '../lib/settings.mjs';

async function fixture(t, options) {
  const dir = await mkdtemp(path.join(tmpdir(), 'net-switch-settings-'));
  t.after(() => rm(dir, { recursive: true, force: true }));
  return { dir, settings: new Settings(dir, options) };
}

test('corrupt settings recover from the backup and keep the exact bad file', async (t) => {
  const { settings } = await fixture(t);
  await writeFile(settings.file, '{broken');
  await writeFile(`${settings.file}.bak`, JSON.stringify({ mainAlias: 'Cable', extra: 42 }));
  const values = await settings.load();
  assert.equal(values.mainAlias, 'Cable');
  assert.equal(values.extra, 42);
  assert.equal(settings.recovery.usedBackup, true);
  assert.match(settings.recovery.reason, /Invalid settings/);
  assert.ok(settings.recovery.savedAs.startsWith(`${settings.file}.corrupt-`));
  assert.equal(await readFile(settings.recovery.savedAs, 'utf8'), '{broken');
  assert.equal(await readFile(settings.file, 'utf8'), '{broken');
});

test('corrupt settings without a usable backup fall back to defaults', async (t) => {
  for (const backup of [undefined, '{broken', '[]']) {
    const { settings } = await fixture(t);
    await writeFile(settings.file, '{broken');
    if (backup !== undefined) await writeFile(`${settings.file}.bak`, backup);
    const values = await settings.load();
    assert.equal(values.mainAlias, null);
    assert.deepEqual(values.secondApps, []);
    assert.equal(values.combine, false);
    assert.equal(settings.recovery.usedBackup, false);
    assert.equal(await readFile(settings.recovery.savedAs, 'utf8'), '{broken');
  }
});

test('JSON values other than plain objects are preserved as corrupt', async (t) => {
  for (const text of ['null', '[]', '42', '"Cable"', 'true']) {
    const { settings } = await fixture(t);
    await writeFile(settings.file, text);
    assert.equal((await settings.load()).mainAlias, null);
    assert.equal(await readFile(settings.recovery.savedAs, 'utf8'), text);
    assert.match(settings.recovery.reason, /plain object/);
  }
});

test('load repairs wrong types per key, retains unknown keys, and strips booster settings', async (t) => {
  const { settings } = await fixture(t);
  await writeFile(settings.file, JSON.stringify({
    mainAlias: 7, mainGuid: false, secondAlias: 'Wi-Fi', secondGuid: '{abc}',
    secondApps: ['app.exe', 8], combine: 'false', extra: { keep: true },
    boost: true, boostTrustSince: 'yesterday',
  }));
  const values = await settings.load();
  assert.equal(values.mainAlias, null);
  assert.equal(values.mainGuid, null);
  assert.equal(values.secondAlias, 'Wi-Fi');
  assert.equal(values.secondGuid, '{abc}');
  assert.deepEqual(values.secondApps, []);
  assert.equal(values.combine, false);
  assert.deepEqual(values.extra, { keep: true });
  assert.equal(Object.hasOwn(values, 'boost'), false);
  assert.equal(Object.hasOwn(values, 'boostTrustSince'), false);
  for (const key of ['mainAlias', 'mainGuid', 'secondApps', 'combine']) assert.ok(settings.recovery.reason.includes(key));
  assert.equal(settings.recovery.savedAs, null);
});

test('a reusable store has its own file and defaults, and clears recovery on a clean load', async (t) => {
  const { dir, settings } = await fixture(t, { fileName: 'undo.json', defaults: { count: 0, name: 'none', enabled: true } });
  assert.deepEqual(await settings.load(), { count: 0, name: 'none', enabled: true });
  assert.equal(settings.recovery, null);
  await writeFile(settings.file, JSON.stringify({ count: 'bad', name: null, enabled: false }));
  assert.deepEqual(await settings.load(), { count: 0, name: null, enabled: false });
  assert.match(settings.recovery.reason, /count/);
  await settings.update({ count: 1 });
  await settings.load();
  assert.equal(settings.recovery, null);
  assert.deepEqual((await readdir(dir)).sort(), ['undo.json', 'undo.json.bak']);
});

test('concurrent updates are serialized and the backup matches the latest successful write', async (t) => {
  const { settings } = await fixture(t, { defaults: { count: 0 } });
  const results = await Promise.all(Array.from({ length: 12 }, () => settings.update((values) => ({ count: values.count + 1 }))));
  assert.deepEqual(results.map((values) => values.count), Array.from({ length: 12 }, (_, i) => i + 1));
  const text = await readFile(settings.file, 'utf8');
  assert.deepEqual(JSON.parse(text), { count: 12 });
  assert.equal(await readFile(`${settings.file}.bak`, 'utf8'), text);
});

test('backup failures are reported without failing a successful update', async (t) => {
  const errors = [];
  const { settings } = await fixture(t, { onBackupError(error) { errors.push(error); throw new Error('reporter failed'); } });
  await mkdir(`${settings.file}.bak`);
  const values = await settings.update({ combine: true });
  assert.equal(values.combine, true);
  assert.equal(JSON.parse(await readFile(settings.file, 'utf8')).combine, true);
  assert.equal(errors.length, 1);
  assert.ok(errors[0].code);
});

test('a failed write leaves memory unchanged and does not block later updates', async (t) => {
  const { settings } = await fixture(t, { defaults: { count: 0 } });
  await mkdir(settings.file);
  await assert.rejects(settings.update({ count: 1 }));
  assert.equal(settings.values.count, 0);
  await rm(settings.file, { recursive: true });
  await settings.update({ count: 2 });
  assert.equal(settings.values.count, 2);
});
