// The record of how Windows was before Net Switch changed it, and the undo
// that puts it back. The window's Undo button and the uninstaller's restore
// (tools/restore-windows.mjs) both use this, so they undo the same way.
import { restoreMetrics, restoreMinimizeConnectionsPolicy } from './platform/windows-network.mjs';
import { Settings } from './settings.mjs';

export const UNDO_FILE = 'windows-undo.json';

// metrics: { [adapter alias]: readMetrics() }; policy: { value } once saved.
export function openUndoRecord(dir, options = {}) {
  return new Settings(dir, { fileName: UNDO_FILE, defaults: { metrics: {}, policy: {} }, ...options });
}

// Whether the record still holds anything to undo.
export function hasChanges(values) {
  return 'value' in values.policy || Object.values(values.metrics).some((metrics) => metrics.length > 0);
}

// What is wrong with a record, entry by entry; empty when it can be trusted.
// The record is the only copy of the person's own Windows settings, so
// anything unexpected stops the undo rather than being skipped or guessed at.
export function validateUndoRecord(values) {
  const problems = [];
  const policy = values?.policy;
  if (!policy || typeof policy !== 'object' || Array.isArray(policy)) {
    problems.push('the policy entry is not an object');
  } else if ('value' in policy && policy.value !== null && !Number.isInteger(policy.value)) {
    problems.push('the policy value is not a number');
  }
  const metrics = values?.metrics;
  if (!metrics || typeof metrics !== 'object' || Array.isArray(metrics)) {
    problems.push('the adapter entries are not an object');
    return problems;
  }
  for (const [alias, records] of Object.entries(metrics)) {
    if (!Array.isArray(records)) {
      problems.push(`${alias}: not a list`);
      continue;
    }
    for (const item of records) {
      const valid =
        item &&
        (item.family === 'IPv4' || item.family === 'IPv6') &&
        typeof item.automatic === 'boolean' &&
        Number.isFinite(item.metric);
      if (!valid) problems.push(`${alias}: an unreadable entry`);
    }
  }
  return problems;
}

// Undoes every recorded change and forgets each one once it is undone, so a
// failure leaves only what is still to do. An adapter that isn't there can't
// be restored; those are returned, and their records kept for next time.
// A policy that can't be written throws, with its record kept. A record that
// fails validation throws before anything is changed.
export async function undoWindowsChanges(record) {
  const problems = validateUndoRecord(record.values);
  if (problems.length > 0) {
    throw new Error(`the Windows undo record is damaged (${problems.join('; ')}), so nothing was undone; it is kept as it is`);
  }
  const unreachable = [];
  if ('value' in record.values.policy) {
    await restoreMinimizeConnectionsPolicy(record.values.policy.value);
    await record.update({ policy: {} });
  }
  for (const [alias, metrics] of Object.entries(record.values.metrics)) {
    try {
      if (metrics.length > 0) await restoreMetrics(alias, metrics);
    } catch {
      unreachable.push(alias);
      continue;
    }
    await record.update((values) => {
      const { [alias]: done, ...left } = values.metrics;
      return { metrics: left };
    });
  }
  return unreachable;
}
