import { once } from 'node:events';
import { LineMonitor } from './monitor.mjs';
import { runFile } from './ps.mjs';

export function parseNetworkSnapshot(text) {
  const value = JSON.parse(text);
  if (!Array.isArray(value?.adapters) || value.adapters.length === 0 ||
      !value.adapters.every((adapter) => typeof adapter?.alias === 'string' && Number.isInteger(adapter.index) &&
        typeof adapter.status === 'string' && Array.isArray(adapter.ipv4s) && adapter.ipv4s.every((ip) => typeof ip === 'string')) ||
      !Array.isArray(value.defaultRoutes) || !value.defaultRoutes.every((route) =>
        typeof route?.gateway === 'string' && typeof route.interfaceAddress === 'string' && Number.isFinite(route.metric)) ||
      !(value.policy === 'absent' || Number.isInteger(value.policy))) {
    throw new Error('The network helper returned an incomplete snapshot.');
  }
  return value;
}

// Shares the meter helpers' watchdog and restart backoff. The safety refresh
// arrives every 30 seconds, so allow longer than that before calling it stuck.
export class NetworkMonitor extends LineMonitor {
  constructor(options) {
    super({ silentMs: 45_000, ...options });
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

  usableAddresses(alias) {
    const adapter = this.snapshot().adapters.find((item) => item.alias === alias);
    // A disconnected interface can retain its static address in Windows'
    // configuration. Node's old address reader omitted interfaces that were down.
    return adapter?.status === 'Up' ? adapter.ipv4s : [];
  }

  async readDefaultRoutes() {
    return this.snapshot().defaultRoutes;
  }

  async ready(timeoutMs = 20_000) {
    if (this.receivedAt) return this.snapshot();
    const [snapshot] = await once(this, 'network', { signal: AbortSignal.timeout(timeoutMs) });
    return snapshot;
  }
}

// Explicit setup changes need a fresh policy reading for Undo, not a value
// cached before somebody else changed the registry. This is never a timer.
export async function readNetworkOnce(helperPath, run = runFile) {
  return parseNetworkSnapshot(await run(helperPath, ['network', '--once'], { timeoutMs: 10_000 }));
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
