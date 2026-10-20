// Focused round-four oracle cases; the existing 25 trace bytes stay frozen.
import assert from 'node:assert/strict';
import { fileURLToPath } from 'node:url';
import { oracle } from './harness.mjs';
import { lines } from './record.mjs';

const metric = [{ family: 'IPv4', automatic: true, metric: 25 }];
export const undoScenarios = [
  { name: 'damaged-policy', undo: { policy: { value: 'bad' }, metrics: { Zebra: metric } } },
  { name: 'damaged-metrics', undo: { policy: { value: 3 }, metrics: { Zebra: [{ family: 'IP', automatic: true, metric: 25 }], Alpha: 'bad' } } },
  { name: 'policy-failure', undo: { policy: { value: 3 }, metrics: { Zebra: metric } }, faults: { policyFailure: 'policy denied' } },
  { name: 'save-failure', undo: { policy: { value: 3 }, metrics: { Zebra: metric } }, faults: { undoWriteFailure: 'disk full' } },
  { name: 'partial-ordered', undo: { policy: { value: 3 }, metrics: { Zebra: metric, Alpha: metric, Done: metric } }, faults: { restoreFailures: { Zebra: 'adapter missing', Alpha: 'access denied' } } },
  { name: 'empty-record', undo: { policy: {}, metrics: { Empty: [] } } },
  { name: 'legacy-ordered', legacyUndo: { policy: 3, metrics: { Zebra: metric, Alpha: metric } },
    undo: { policy: {}, metrics: { Zebra: [{ family: 'IPv4', automatic: false, metric: 77 }], Current: metric } },
    faults: { restoreFailures: { Zebra: 'adapter missing', Alpha: 'adapter missing', Current: 'adapter missing' } } },
];

export async function recordUndo() {
  const cases = [];
  for (const scenario of undoScenarios) {
    const entries = [];
    const run = await oracle({ initial: { lines, ...(scenario.legacyUndo ? { setupUndo: scenario.legacyUndo } : {}) }, environment: { undo: scenario.undo }, trace: (direction, kind, value) => entries.push({ direction, kind, value }) });
    entries.length = 0;
    Object.assign(run.environment, scenario.faults);
    const response = await run.request('POST', '/api/setup/undo', {});
    const expected = {
      status: response.status, error: response.body.error ?? null,
      remaining: JSON.parse(run.files.get('/oracle/data/windows-undo.json')),
      policy: run.environment.policy,
      operations: entries.filter(({ kind, value }) => kind === 'async-result' && ['network.restoreMetrics', 'network.restoreMinimizeConnectionsPolicy', 'platform.readMinimizeConnectionsPolicy', 'platform.detectAdapters'].includes(value.operation)).map(({ value }) => ({ operation: value.operation, args: value.args, ok: value.ok })),
      logs: entries.filter(({ kind, value }) => kind === 'log' && value.text.startsWith('undo failed:')).map(({ value }) => value.text),
    };
    assert.equal(response.status, scenario.name === 'empty-record' ? 200 : 400);
    if (scenario.name.startsWith('damaged-')) assert.equal(expected.operations.length, 0);
    if (scenario.name === 'partial-ordered') {
      assert.match(expected.error, /Connect Zebra and Alpha again/);
      assert.deepEqual(Object.keys(expected.remaining.metrics), ['Zebra', 'Alpha']);
      assert.equal(expected.operations.at(-1).operation, 'platform.detectAdapters');
    }
    if (scenario.name === 'empty-record') assert(!expected.operations.some(({ operation }) => operation === 'network.restoreMetrics'));
    if (scenario.name === 'legacy-ordered') {
      assert.match(expected.error, /Connect Zebra and Alpha and Current again/);
      assert.equal(expected.remaining.metrics.Zebra[0].metric, 77);
    }
    cases.push({ ...scenario, expected });
  }
  return cases;
}

if (process.argv[1] === fileURLToPath(import.meta.url)) console.log(JSON.stringify(await recordUndo(), null, 2));
