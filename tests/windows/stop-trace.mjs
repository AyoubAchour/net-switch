import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { readdir } from 'node:fs/promises';
import path from 'node:path';
import { hostedOnly } from './testisp/harness.mjs';

hostedOnly();
const directory = path.resolve('dist/windows-lifecycle');
const files = (await readdir(directory)).filter((name) => /^engine-stop-.*\.trace$/.test(name));
assert(files.length > 0, 'The hosted scheduler trace did not run');
for (const file of files) {
  const text = execFileSync('go', ['tool', 'trace', '-d=1', path.join(directory, file)],
    { encoding: 'utf8', windowsHide: true, maxBuffer: 64 << 20 });
  const blocks = text.split(/(?=^M=)/m);
  const states = new Map(), intervals = [], control = [], processors = [];
  for (const block of blocks) {
    const first = block.split('\n', 1)[0];
    if (/RangeBegin|RangeEnd|RegionBegin|RegionEnd|StopTheWorld/.test(first)) control.push(block.trim());
    if (/Resource=Proc\(/.test(first)) processors.push(first);
    const match = first.match(/StateTransition Time=(\d+) Resource=Goroutine\((\d+)\).* (\w+)->(\w+)/);
    if (!match) continue;
    const [, rawTime, id, from, to] = match, time = Number(rawTime);
    const previous = states.get(id);
    if (previous) {
      const ms = (time - previous.time) / 1e6;
      if (ms >= 5 && /engine|wintun|journal/.test(previous.block)) {
        intervals.push({ goroutine: id, state: from, ms, start: previous.block.trim(), end: block.trim() });
      }
    }
    states.set(id, { time, state: to, block });
  }
  console.log(`WINDOWS STOP SCHEDULER ${JSON.stringify({ file, control, processors, longest: intervals.sort((a, b) => b.ms - a.ms).slice(0, 30),
    parsedEvents: blocks.length, parsedGoroutines: states.size })}`);
  assert(states.size > 0, 'Scheduler parser did not recognize Go trace events');
}
