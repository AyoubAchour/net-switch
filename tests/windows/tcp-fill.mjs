// Client-side allocation refusals in the Windows TCP fill (SYSTEM-DESIGN
// 5.9, "Amended"): Windows' automatic port choice can refuse a bind or
// ConnectEx with WSAENOBUFS/WSAEADDRINUSE while the dynamic pool still has
// free ports. That refusal belongs to the test app's own socket, not to the
// engine's port allocation, so it gets exactly one explicit, reported
// re-attempt on a fresh socket. A refusal that survives its re-attempt is
// counted, and the fill stops as before. Nothing is retried silently.
//
// Acceptance x64 job 120239285886 stopped at Held 992 because one client
// connect was refused and the batch was treated as the OS limit. The UDP fill
// already follows the same rule in udp-capacity.mjs (job 119667481104).

export const clientAllocationCodes = Object.freeze(['ENOBUFS', 'EADDRINUSE']);
export const clientAllocationCalls = Object.freeze(['bind', 'connect']);

const windowsNames = Object.freeze({ ENOBUFS: 'WSAENOBUFS', EADDRINUSE: 'WSAEADDRINUSE' });

export function windowsErrorName(code) {
  return windowsNames[code] ?? null;
}

// Only the app's own bind or connect failing to allocate a port qualifies.
// The client records source 'client' for every error it sees on its socket;
// an engine-side refusal reaches the app as ECONNRESET/ECONNREFUSED after its
// SYN, so it can never match here.
export function clientAllocationFailure(failure) {
  return Boolean(failure) && failure.source === 'client' &&
    clientAllocationCalls.includes(failure.call) &&
    clientAllocationCodes.includes(failure.code);
}

export function emptyFillEvidence() {
  return {
    clientFirstRefusals: {}, clientReattempts: {}, clientReattemptSuccesses: {},
    clientReattemptFailures: {}, clientFinalRefusals: {}, records: [],
  };
}

// One record per client-side failure, with the Windows error code and name,
// the local/remote tuple where the socket reported one, the batch and attempt
// numbers, and the time the failure was seen.
export function describeClientFailure(failure, { request, batch, attempt, phase, at }) {
  return {
    at, phase, request, batch, attempt,
    code: failure.code ?? null, name: windowsErrorName(failure.code), errno: failure.errno ?? null,
    syscall: failure.call ?? null, local: failure.local ?? null, remote: failure.remote ?? null,
    ms: Number.isFinite(failure.ms) ? failure.ms : null, message: failure.message ?? null,
  };
}

const count = (map, code) => { const key = code ?? 'UNKNOWN'; map[key] = (map[key] ?? 0) + 1; };

// Run one fill attempt. open() must return { socket, ms, startMS, endMS } on
// success or { failure } on error, and is called a second time (a fresh
// socket) only for a client-side allocation refusal. The returned failure is
// the one that counts: the re-attempt's if it ran, otherwise the first.
export async function openWithClientReattempt({ open, evidence, request, batch, attempt, now = () => new Date().toISOString() }) {
  const first = await open();
  if (!first.failure) return { ...first, reattempted: false };
  if (!clientAllocationFailure(first.failure)) {
    count(evidence.clientFinalRefusals, first.failure.code);
    evidence.records.push({ ...describeClientFailure(first.failure, { request, batch, attempt, phase: 'first', at: now() }),
      counted: true, outcome: 'counted: not a client port allocation refusal' });
    return { ...first, reattempted: false };
  }
  count(evidence.clientFirstRefusals, first.failure.code);
  const record = { ...describeClientFailure(first.failure, { request, batch, attempt, phase: 'first', at: now() }), counted: false };
  evidence.records.push(record);
  const again = await open();
  count(evidence.clientReattempts, first.failure.code);
  if (!again.failure) {
    count(evidence.clientReattemptSuccesses, first.failure.code);
    record.outcome = 'reported: succeeded on one re-attempt';
    return { ...again, reattempted: true };
  }
  count(evidence.clientReattemptFailures, first.failure.code);
  count(evidence.clientFinalRefusals, again.failure.code);
  record.outcome = 'counted: re-attempt failed';
  record.counted = true;
  record.reattempt = { ...describeClientFailure(again.failure, { request, batch, attempt, phase: 'reattempt', at: now() }), counted: true };
  evidence.records.push(record.reattempt);
  return { ...again, reattempted: true };
}

export function mergeFillEvidence(target, source) {
  for (const key of ['clientFirstRefusals', 'clientReattempts', 'clientReattemptSuccesses',
    'clientReattemptFailures', 'clientFinalRefusals']) {
    for (const [code, value] of Object.entries(source?.[key] ?? {})) target[key][code] = (target[key][code] ?? 0) + value;
  }
  target.records.push(...(source?.records ?? []));
  return target;
}
