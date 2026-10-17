import { once } from 'node:events';
import { LineMonitor } from './monitor.mjs';
import { runFile } from './ps.mjs';
import { readDefaultRoutes } from './network.mjs';

export function parseNetworkSnapshot(text) {
  const value = JSON.parse(text);
  if (!Number.isSafeInteger(value?.readAt) || value.readAt <= 0 || !Array.isArray(value?.adapters) || value.adapters.length === 0 ||
      !value.adapters.every((adapter) => typeof adapter?.alias === 'string' && Number.isInteger(adapter.index) &&
        typeof adapter.status === 'string' && Array.isArray(adapter.ipv4s) && adapter.ipv4s.every((ip) => typeof ip === 'string')) ||
      !Array.isArray(value.defaultRoutes) || !value.defaultRoutes.every((route) =>
        typeof route?.gateway === 'string' && typeof route.interfaceAddress === 'string' && Number.isFinite(route.metric)) ||
      !(value.policy === 'absent' || value.policy === 'unknown' || Number.isInteger(value.policy))) {
    throw new Error('The network helper returned an incomplete snapshot.');
  }
  return value;
}

// Shares the meter helpers' watchdog and restart backoff. The safety refresh
// arrives every 10 seconds, so allow longer than that before calling it stuck.
export class NetworkMonitor extends LineMonitor {
  constructor(options) {
    super({ silentMs: 15_000, ...options });
    this.fallbackRoutes = options.readDefaultRoutes ?? readDefaultRoutes;
    this.latest = null;
    this.receivedAt = 0;
    this.on('helperExit', () => { this.receivedAt = 0; });
  }

  start() {
    if (this.helpers.get('network')?.child) return;
    this.stopped = false;
    this.launch('network', () => this.spawnHelper(this.helperPath, ['network', '--parent', String(process.pid)]));
  }

  stop() {
    super.stop();
    this.receivedAt = 0;
  }

  handleLine(line) {
    let snapshot;
    try {
      snapshot = parseNetworkSnapshot(line);
    } catch {
      return false;
    }
    this.latest = snapshot;
    this.receivedAt = Date.now();
    this.emit('network', snapshot);
    return true;
  }

  snapshot() {
    if (!this.receivedAt || Date.now() - this.receivedAt > this.silentMs) {
      throw new Error('The network helper has no current snapshot.');
    }
    return this.latest;
  }

  async readDefaultRoutes() {
    try {
      return this.snapshot().defaultRoutes;
    } catch {
      return this.fallbackRoutes();
    }
  }

  async ready(timeoutMs = 20_000) {
    if (this.receivedAt) return this.snapshot();
    const [snapshot] = await once(this, 'network', { signal: AbortSignal.timeout(timeoutMs) });
    return snapshot;
  }
}

// Explicit setup changes request a new adapter scan through the update queue.
export async function readNetworkOnce(helperPath, run = runFile) {
  return parseNetworkSnapshot(await run(helperPath, ['network', '--once'], { timeoutMs: 10_000 }));
}

// Undo needs an authoritative registry read, independent of adapter discovery.
export async function readPolicyOnce(helperPath, run = runFile) {
  const { policy } = JSON.parse(await run(helperPath, ['policy'], { timeoutMs: 10_000 }));
  if (policy === 'absent') return null;
  if (Number.isInteger(policy)) return policy;
  throw new Error('The policy helper did not return a known Wi-Fi policy.');
}

// Both stream events and explicit reads enter this queue before reading/applying.
// Cross-process snapshots carry their read start time so a delayed stream line
// cannot overwrite a newer one-off read or count the same reading twice.
export class NetworkUpdates {
  constructor(apply, read, log = () => {}) {
    this.apply = apply;
    this.read = read;
    this.log = log;
    this.pending = Promise.resolve();
    this.lastReadAt = 0;
  }

  refresh(snapshot = null) {
    this.pending = this.pending.then(async () => {
      const next = snapshot ?? await this.read();
      if (next.readAt <= this.lastReadAt) return;
      await this.apply(next);
      this.lastReadAt = next.readAt;
    }).catch((error) => this.log(`network update failed: ${error.message}`));
    return this.pending;
  }
}

export async function quickProbe(helperPath, interfaceIndex, {
  targets = ['1.1.1.1:443', '8.8.8.8:443'], timeoutMs = 2000, run = runFile,
} = {}) {
  if (!Number.isInteger(interfaceIndex) || interfaceIndex < 1 || interfaceIndex > 0xffffffff ||
      !Number.isInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 60_000 || !Array.isArray(targets) || targets.length === 0) {
    throw new Error('A probe needs an interface index, targets and a timeout from 1 to 60000 ms.');
  }
  const text = await run(helperPath, [
    'probe', '--interface-index', String(interfaceIndex), '--targets', targets.join(','), '--timeout-ms', String(timeoutMs),
  ], { timeoutMs: timeoutMs + 3000 });
  const result = JSON.parse(text);
  if (result?.ok === true && Number.isFinite(result.ms) && result.ms >= 0 && targets.includes(result.target)) return result;
  if (result?.ok === false && typeof result.error === 'string' && result.error.length > 0) return result;
  throw new Error('The probe helper returned an invalid result.');
}
