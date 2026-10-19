import { Usage, periodStart } from '../../lib/usage.mjs';

// Zone-aware public-call vectors, including the instant before/after each gap.
const cases = [];
for (const [timezone, transition] of [
  ['America/Santiago', '2026-09-06T04:00:00Z'],
  ['America/Havana', '2026-03-08T05:00:00Z'],
  ['Africa/Cairo', '2026-04-23T22:00:00Z'],
  ['America/Havana', '2026-11-01T05:00:00Z'],
]) {
  process.env.TZ = timezone;
  const now = Date.parse(transition);
  const cap = { bytes: 100, period: 'day' };
  const lines = [{ id: 'a1', cap }];
  const u = new Usage();
  const calls = [{ name: 'Usage', id: 1, args: [], result: null }];
  for (const [index, delta] of [-2000, -1000, 0, 1000, 4123].entries()) {
    const counters = { a1: { rx: index * 80, tx: 0 } };
    const rates = { a1: index ? 300000 : 1e8 };
    const at = now + delta;
    calls.push({ name: 'periodStart', args: [cap, at], result: periodStart(cap, at) });
    u.ingest(lines, (line) => counters[line.id], (line) => rates[line.id], at);
    calls.push({ name: 'ingest', id: 1, args: [lines, counters, rates, at], result: null });
    calls.push({ name: 'toJSON', id: 1, args: [], result: structuredClone(u.toJSON()) });
    calls.push({ name: 'exhausted', id: 1, args: [lines, at], result: [...u.exhausted(lines, at)] });
  }
  cases.push({ name: `${timezone} at ${transition}`, timezone, calls });
}
console.log(JSON.stringify(cases));
