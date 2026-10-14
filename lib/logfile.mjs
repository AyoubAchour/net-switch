import { appendFile, rename, stat } from 'node:fs/promises';
import { setTimeout as delay } from 'node:timers/promises';

export function createLog(file, { maxBytes = 2 * 1024 * 1024, timestamp = true } = {}) {
  let size;
  let queue = Promise.resolve();

  async function readSize() {
    try {
      size = (await stat(file)).size;
    } catch (error) {
      if (error.code !== 'ENOENT') throw error;
      size = 0;
    }
  }

  async function rotateFile() {
    for (let attempt = 0; ; attempt += 1) {
      try {
        await rename(file, `${file}.1`);
        break;
      } catch (error) {
        if (attempt >= 10 || !['EPERM', 'EBUSY', 'EACCES'].includes(error.code)) break;
        await delay(50);
      }
    }
    // A failed rename leaves the current log in place; keep writing there.
    await readSize();
  }

  function enqueue(run) {
    const result = queue.then(run).catch(() => {});
    queue = result;
    return result;
  }

  return {
    append(line) {
      return enqueue(async () => {
        if (size === undefined) await readSize();
        if (size > maxBytes) await rotateFile();
        const text = `${timestamp ? `${new Date().toISOString()} ` : ''}${line}\n`;
        await appendFile(file, text, 'utf8');
        size += Buffer.byteLength(text);
      });
    },
    rotate() {
      return enqueue(rotateFile);
    },
  };
}
