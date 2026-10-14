import assert from 'node:assert/strict';
import { mkdir, mkdtemp, readFile, readdir, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { test } from 'node:test';
import { createLog } from '../lib/logfile.mjs';

async function fixture(t) {
  const dir = await mkdtemp(path.join(tmpdir(), 'net-switch-log-'));
  t.after(() => rm(dir, { recursive: true, force: true }));
  return { dir, file: path.join(dir, 'engine.log') };
}

test('the size cap counts bytes and rotates before the next write after exceeding it', async (t) => {
  const { file } = await fixture(t);
  const log = createLog(file, { maxBytes: 4, timestamp: false });
  await log.append('éé');
  await log.append('new');
  assert.equal(await readFile(`${file}.1`, 'utf8'), 'éé\n');
  assert.equal(await readFile(file, 'utf8'), 'new\n');
});

test('an existing oversized file is rotated on the first append', async (t) => {
  const { file } = await fixture(t);
  await writeFile(file, 'previous run\n');
  await createLog(file, { maxBytes: 4, timestamp: false }).append('next');
  assert.equal(await readFile(`${file}.1`, 'utf8'), 'previous run\n');
  assert.equal(await readFile(file, 'utf8'), 'next\n');
});

test('concurrent appends retain call order', async (t) => {
  const { file } = await fixture(t);
  const log = createLog(file, { timestamp: false });
  const lines = Array.from({ length: 50 }, (_, i) => `line ${i}`);
  await Promise.all(lines.map((line) => log.append(line)));
  assert.equal(await readFile(file, 'utf8'), `${lines.join('\n')}\n`);
});

test('explicit rotation shares the write queue and keeps exactly one previous file', async (t) => {
  const { dir, file } = await fixture(t);
  const log = createLog(file, { timestamp: false });
  await Promise.all([log.append('first'), log.rotate(), log.append('second'), log.rotate(), log.append('third')]);
  assert.equal(await readFile(file, 'utf8'), 'third\n');
  assert.equal(await readFile(`${file}.1`, 'utf8'), 'second\n');
  assert.deepEqual((await readdir(dir)).sort(), ['engine.log', 'engine.log.1']);
});

test('failed rotation keeps appending to the current log', async (t) => {
  const { file } = await fixture(t);
  await mkdir(`${file}.1`);
  const log = createLog(file, { maxBytes: 1, timestamp: false });
  await log.append('first');
  await log.append('second');
  assert.equal(await readFile(file, 'utf8'), 'first\nsecond\n');
});

test('a missing directory never rejects and later writes can recover', async (t) => {
  const { dir } = await fixture(t);
  const missing = path.join(dir, 'missing');
  const file = path.join(missing, 'engine.log');
  const log = createLog(file, { timestamp: false });
  await Promise.all([log.append('lost'), log.rotate(), log.append('also lost')]);
  await mkdir(missing);
  await log.append('saved');
  assert.equal(await readFile(file, 'utf8'), 'saved\n');
});

test('timestamps are enabled by default', async (t) => {
  const { file } = await fixture(t);
  await createLog(file).append('ready');
  assert.match(await readFile(file, 'utf8'), /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z ready\n$/);
});
