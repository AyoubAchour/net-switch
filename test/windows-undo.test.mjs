import assert from 'node:assert/strict';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { test } from 'node:test';
import { execFile } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';
import { hasChanges, openUndoRecord, UNDO_FILE, undoWindowsChanges, validateUndoRecord } from '../lib/windows-undo.mjs';

const RESTORE = fileURLToPath(new URL('../tools/restore-windows.mjs', import.meta.url));
const run = promisify(execFile);

// The restore tool's exit code, run against a folder: 0 lets the uninstaller delete the record.
async function restoreExitCode(dir) {
  try {
    await run(process.execPath, [RESTORE, '--machine-data', dir]);
    return 0;
  } catch (error) {
    return error.code;
  }
}

test('an undo record holds changes only when a policy was saved or an adapter has settings to restore', () => {
  assert.equal(hasChanges({ metrics: {}, policy: {} }), false);
  // An empty adapter record, from versions that saved a failed reading, holds nothing to restore.
  assert.equal(hasChanges({ metrics: { 'Wi-Fi': [] }, policy: {} }), false);
  assert.equal(hasChanges({ metrics: {}, policy: { value: null } }), true);
  assert.equal(hasChanges({ metrics: { 'Wi-Fi': [{ family: 'IPv4', automatic: true, metric: 25 }] }, policy: {} }), true);
});

test('a missing undo record reads as nothing to undo, and a saved one is read back as written', async () => {
  const dir = await mkdtemp(path.join(tmpdir(), 'net-switch-undo-'));
  try {
    const empty = openUndoRecord(dir);
    await empty.load();
    assert.deepEqual(empty.values, { metrics: {}, policy: {} });
    assert.equal(hasChanges(empty.values), false);

    const saved = { metrics: { 'Wi-Fi': [{ family: 'IPv4', automatic: false, metric: 60 }] }, policy: { value: 1 } };
    await writeFile(path.join(dir, UNDO_FILE), JSON.stringify(saved));
    const record = openUndoRecord(dir);
    await record.load();
    assert.deepEqual(record.values, saved);
    assert.equal(hasChanges(record.values), true);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('an undo record with unexpected entries is reported, and undoing it changes nothing', async () => {
  assert.deepEqual(validateUndoRecord({ metrics: {}, policy: {} }), []);
  assert.deepEqual(validateUndoRecord({ metrics: {}, policy: { value: null } }), []);
  assert.equal(validateUndoRecord({ metrics: {}, policy: { value: 'one' } }).length, 1);
  assert.equal(validateUndoRecord({ metrics: { 'Wi-Fi': 'IPv4' }, policy: {} }).length, 1);
  assert.equal(validateUndoRecord({ metrics: { 'Wi-Fi': [{ family: 'IPv4' }] }, policy: {} }).length, 1);
  const damaged = { values: { metrics: { 'Wi-Fi': [{ family: 'IPX', automatic: true, metric: 1 }] }, policy: {} } };
  await assert.rejects(undoWindowsChanges(damaged), /damaged/);
});

test('the uninstaller may delete the record only when it is missing or holds nothing, never when it is damaged', async () => {
  const dir = await mkdtemp(path.join(tmpdir(), 'net-switch-restore-'));
  try {
    // No record at all.
    assert.equal(await restoreExitCode(dir), 0);
    // A record with nothing left in it.
    await writeFile(path.join(dir, UNDO_FILE), JSON.stringify({ metrics: {}, policy: {} }));
    assert.equal(await restoreExitCode(dir), 0);
    // A record that doesn't parse: kept, exit 1, even though it would load as empty defaults.
    await writeFile(path.join(dir, UNDO_FILE), '{ "metrics": ');
    assert.equal(await restoreExitCode(dir), 1);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
  const invalid = await mkdtemp(path.join(tmpdir(), 'net-switch-restore-'));
  try {
    // Parses, but an entry can't be trusted.
    await writeFile(path.join(invalid, UNDO_FILE), JSON.stringify({ metrics: { 'Wi-Fi': [{ family: 'IPv4', automatic: 'yes', metric: 5 }] }, policy: {} }));
    assert.equal(await restoreExitCode(invalid), 1);
  } finally {
    await rm(invalid, { recursive: true, force: true });
  }
});
