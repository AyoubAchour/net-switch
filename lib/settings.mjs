import { randomUUID } from 'node:crypto';
import { copyFile, readFile, rename, rm, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';

const DEFAULTS = {
  mainAlias: null,
  mainGuid: null,
  secondAlias: null,
  secondGuid: null,
  secondApps: [],
  // Apps kept on the cable, which combining leaves out.
  cableApps: [],
  combine: false,
  // Look for a newer release on GitHub twice a day.
  checkForUpdates: true,
  // The release the person said "not now" to.
  skippedUpdate: null,
};

function isPlainObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
    && Object.getPrototypeOf(value) === Object.prototype;
}

function parseSettings(text) {
  const saved = JSON.parse(text);
  if (!isPlainObject(saved)) throw new SyntaxError('The JSON value is not a plain object.');
  return saved;
}

function validValue(value, fallback) {
  if (fallback === null || typeof fallback === 'string') return value === null || typeof value === 'string';
  if (Array.isArray(fallback)) return Array.isArray(value) && value.every((item) => typeof item === 'string');
  if (isPlainObject(fallback)) return isPlainObject(value);
  if (typeof fallback === 'number') return typeof value === 'number' && Number.isFinite(value);
  return typeof value === typeof fallback;
}

// Write to a uniquely named temp file, then swap it in, so readers never see
// half a file and two writers never share a temp file. Windows refuses the
// swap while another process has the file open, so retry briefly.
export async function writeFileAtomic(file, text) {
  const temp = `${file}.${randomUUID()}.tmp`;
  await writeFile(temp, text, 'utf8');
  for (let attempt = 0; ; attempt += 1) {
    try {
      await rename(temp, file);
      return;
    } catch (error) {
      if (attempt >= 10 || !['EPERM', 'EBUSY', 'EACCES'].includes(error.code)) {
        await rm(temp, { force: true });
        throw error;
      }
      await delay(50);
    }
  }
}

export class Settings {
  constructor(dataDir, { fileName = 'settings.json', defaults = DEFAULTS, onBackupError = () => {} } = {}) {
    this.file = path.join(dataDir, fileName);
    this.defaults = structuredClone(defaults);
    this.values = structuredClone(this.defaults);
    this.onBackupError = onBackupError;
    this.recovery = null;
    this.queue = Promise.resolve();
  }

  async load() {
    this.recovery = null;
    let saved;
    try {
      saved = parseSettings(await readFile(this.file, 'utf8'));
    } catch (error) {
      if (error instanceof SyntaxError) {
        const savedAs = `${this.file}.corrupt-${new Date().toISOString().replace(/[:.]/g, '-')}-${randomUUID()}`;
        await copyFile(this.file, savedAs);
        this.recovery = { reason: `Invalid settings: ${error.message}`, savedAs, usedBackup: false };
        try {
          saved = parseSettings(await readFile(`${this.file}.bak`, 'utf8'));
          this.recovery.usedBackup = true;
        } catch (backupError) {
          if (!(backupError instanceof SyntaxError) && backupError.code !== 'ENOENT') throw backupError;
          this.recovery.reason += ` Backup unavailable: ${backupError.message}`;
        }
      } else if (error.code !== 'ENOENT') throw error;
    }
    const values = { ...structuredClone(this.defaults), ...saved };
    const invalid = [];
    for (const [key, fallback] of Object.entries(this.defaults)) {
      if (saved && Object.hasOwn(saved, key) && !validValue(saved[key], fallback)) {
        values[key] = structuredClone(fallback);
        invalid.push(key);
      }
    }
    if (invalid.length > 0) {
      this.recovery ??= { reason: '', savedAs: null, usedBackup: false };
      this.recovery.reason = [this.recovery.reason, `Invalid types reset to defaults: ${invalid.join(', ')}.`].filter(Boolean).join(' ');
    }
    delete values.boost;
    delete values.boostTrustSince;
    this.values = values;
    return this.values;
  }

  // Updates run one at a time, and the in-memory values change only once the
  // file is written, so a failed write never leaves the screen ahead of disk.
  update(changes) {
    const run = async () => {
      const next = { ...this.values, ...(typeof changes === 'function' ? changes(this.values) : changes) };
      const text = JSON.stringify(next, null, 2);
      await writeFileAtomic(this.file, text);
      this.values = next;
      try {
        await writeFileAtomic(`${this.file}.bak`, text);
      } catch (error) {
        // A reporting callback must not turn a successful save into a failed one.
        try { await this.onBackupError(error); } catch {}
      }
      return next;
    };
    const result = this.queue.then(run, run);
    this.queue = result.catch(() => {});
    return result;
  }
}
