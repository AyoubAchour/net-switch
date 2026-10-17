// What each line has used this period, for data caps, and how fast each line
// can go, for Auto combining. Pure: the caller passes the adapter counters and
// the clock, and saves toJSON() somewhere.

// The period a cap counts over starts at local midnight ('day'), or on the
// cap's reset day of the month at local midnight ('month'; the 1st unless the
// person picked another day, since phone plans renew on their own date).
export function periodStart(cap, now) {
  const date = new Date(now);
  if (cap?.period === 'day') return new Date(date.getFullYear(), date.getMonth(), date.getDate()).getTime();
  const day = Math.min(Math.max(Math.trunc(cap?.resetDay ?? 1) || 1, 1), 28);
  const thisMonth = new Date(date.getFullYear(), date.getMonth(), day).getTime();
  return thisMonth <= now ? thisMonth : new Date(date.getFullYear(), date.getMonth() - 1, day).getTime();
}

// A line counts as busy, so its speed says something about what it can do,
// above this download speed. Below it, the line is only showing what its apps
// asked for.
export const BUSY_BYTES_PER_SECOND = 256 * 1024;
// A line's top speed fades by half over this much busy time, so a line that
// got slower (a phone moved to a weaker signal) is followed within a few hours
// of use. Idle time doesn't fade it: idle says nothing about the line.
export const PEAK_HALF_LIFE_MS = 2 * 60 * 60_000;
// Gaps between readings longer than this count as this, so a pause in the
// readings doesn't fade a peak all at once.
const MAX_STEP_MS = 5000;

export class Usage {
  constructor() {
    // { [lineId]: { bytes, periodStart } }
    this.lines = {};
    // { [lineId]: bytes per second }
    this.peaks = {};
    // Last adapter totals seen, by line id: { rx, tx }. Not saved: counters
    // restart with Windows and with the adapter.
    this.counters = {};
    this.peakAt = {};
  }

  load(saved) {
    if (saved && typeof saved === 'object') {
      for (const [id, entry] of Object.entries(saved.lines ?? {})) {
        if (Number.isFinite(entry?.bytes) && Number.isFinite(entry?.periodStart)) {
          this.lines[id] = { bytes: Math.max(0, entry.bytes), periodStart: entry.periodStart };
        }
      }
      for (const [id, peak] of Object.entries(saved.peaks ?? {})) {
        if (Number.isFinite(peak) && peak > 0) this.peaks[id] = peak;
      }
    }
    return this;
  }

  toJSON() {
    return { lines: this.lines, peaks: this.peaks };
  }

  // Lines Net Switch no longer has are forgotten.
  keepOnly(ids) {
    const keep = new Set(ids);
    for (const store of [this.lines, this.peaks, this.counters, this.peakAt]) {
      for (const id of Object.keys(store)) if (!keep.has(id)) delete store[id];
    }
  }

  // One reading. lines: [{ id, cap }]; counterOf(line) gives the adapter's
  // byte totals { rx, tx } or null; rateOf(line) its download speed or null.
  ingest(lines, counterOf, rateOf, now) {
    for (const line of lines) {
      const start = periodStart(line.cap, now);
      const entry = (this.lines[line.id] ??= { bytes: 0, periodStart: start });
      // A new period starts from zero.
      if (entry.periodStart !== start) {
        entry.bytes = 0;
        entry.periodStart = start;
      }
      const counter = counterOf(line);
      const before = this.counters[line.id];
      if (counter) {
        if (before) {
          const rx = counter.rx - before.rx;
          const tx = counter.tx - before.tx;
          // Counters start over when the adapter reconnects: what they show
          // since is all new.
          entry.bytes += (rx >= 0 ? rx : counter.rx) + (tx >= 0 ? tx : counter.tx);
        }
        this.counters[line.id] = { rx: counter.rx, tx: counter.tx };
      }
      this.notePeak(line.id, rateOf(line), now);
    }
  }

  notePeak(id, rate, now) {
    if (!Number.isFinite(rate) || rate < BUSY_BYTES_PER_SECOND) {
      delete this.peakAt[id];
      return;
    }
    const step = this.peakAt[id] === undefined ? 0 : Math.min(now - this.peakAt[id], MAX_STEP_MS);
    this.peakAt[id] = now;
    const faded = (this.peaks[id] ?? 0) * 0.5 ** (step / PEAK_HALF_LIFE_MS);
    this.peaks[id] = Math.max(rate, faded);
  }

  used(id) {
    return this.lines[id] ?? null;
  }

  // Lines whose cap is reached in the current period.
  exhausted(lines, now) {
    const ids = new Set();
    for (const line of lines) {
      if (!line.cap) continue;
      const entry = this.lines[line.id];
      if (entry && entry.periodStart === periodStart(line.cap, now) && entry.bytes >= line.cap.bytes) ids.add(line.id);
    }
    return ids;
  }

  // Weights for Auto combining: each line's top speed. A line not measured
  // yet gets the average of the others, so it gets a fair try; with nothing
  // measured, all are equal.
  autoWeights(lines) {
    const known = lines.map((line) => this.peaks[line.id]).filter((peak) => peak > 0);
    const fallback = known.length > 0 ? known.reduce((sum, peak) => sum + peak, 0) / known.length : 1;
    return Object.fromEntries(lines.map((line) => [line.id, this.peaks[line.id] > 0 ? this.peaks[line.id] : fallback]));
  }
}
