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
  await writeFile(`${settings.file}.bak`, JSON.stringify({ combine: true, extra: 42 }));
  const values = await settings.load();
  assert.equal(values.combine, true);
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
    assert.deepEqual(values.lines, []);
    assert.deepEqual(values.appLines, {});
    assert.equal(values.combine, false);
    assert.equal(values.combineMode, 'auto');
    assert.deepEqual(values.probeTargets, ['1.1.1.1:443', '8.8.8.8:443']);
    assert.equal(settings.recovery.usedBackup, false);
    assert.equal(await readFile(settings.recovery.savedAs, 'utf8'), '{broken');
  }
});

test('JSON values other than plain objects are preserved as corrupt', async (t) => {
  for (const text of ['null', '[]', '42', '"Cable"', 'true']) {
    const { settings } = await fixture(t);
    await writeFile(settings.file, text);
    assert.deepEqual((await settings.load()).lines, []);
    assert.equal(await readFile(settings.recovery.savedAs, 'utf8'), text);
    assert.match(settings.recovery.reason, /plain object/);
  }
});

test('load repairs wrong types per key, retains unknown keys, and strips booster settings', async (t) => {
  const { settings } = await fixture(t);
  const line = { id: 'a1', alias: 'Ethernet' };
  await writeFile(settings.file, JSON.stringify({
    lines: [line, 'Wi-Fi'], appLines: ['app.exe'], probeTargets: ['1.1.1.1:443', 8],
    combine: 'false', combineMode: 'manual', extra: { keep: true },
    // Settings from 0.2.0 stay for the migration to lines to read.
    secondAlias: 'Wi-Fi',
    boost: true, boostTrustSince: 'yesterday',
  }));
  const values = await settings.load();
  assert.deepEqual(values.lines, []);
  assert.deepEqual(values.appLines, {});
  assert.deepEqual(values.probeTargets, ['1.1.1.1:443', '8.8.8.8:443']);
  assert.equal(values.combine, false);
  assert.equal(values.combineMode, 'manual');
  assert.equal(values.secondAlias, 'Wi-Fi');
  assert.deepEqual(values.extra, { keep: true });
  assert.equal(Object.hasOwn(values, 'boost'), false);
  assert.equal(Object.hasOwn(values, 'boostTrustSince'), false);
  for (const key of ['lines', 'appLines', 'probeTargets', 'combine']) assert.ok(settings.recovery.reason.includes(key));
  assert.equal(settings.recovery.savedAs, null);

  // A list of lines that are all objects is kept as it is; lib/lines.mjs checks each one.
  await writeFile(settings.file, JSON.stringify({ lines: [line] }));
  assert.deepEqual((await settings.load()).lines, [line]);
});

test('a key updated to undefined is removed, in memory and on disk', async (t) => {
  const { settings } = await fixture(t);
  await settings.update({ secondAlias: 'Wi-Fi' });
  await settings.update({ secondAlias: undefined });
  assert.equal(Object.hasOwn(settings.values, 'secondAlias'), false);
  assert.equal(Object.hasOwn(JSON.parse(await readFile(settings.file, 'utf8')), 'secondAlias'), false);
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
