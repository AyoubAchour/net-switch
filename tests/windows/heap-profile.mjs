import assert from 'node:assert/strict';

export const heapLimit = Math.floor(512 * 1024 * 1024 * 0.9);

export async function captureHeap(server, label, heldTCP, heldUDP, baseline) {
  const capture = await server.api('engine-heap', { label });
  assert.equal(capture.MemoryLimit, 512 * 1024 * 1024, 'Capture changed the release memory limit');
  assert.equal(capture.GOGC, 100, 'Capture changed the release GC target');
  assert(capture.Instrumented && capture.Build.some((setting) =>
    setting.Key === '-tags' && setting.Value.includes('netswitch_handlecheck')),
  'Capture did not identify its instrumented build');
  assert(capture.Process?.workingSetBytes > 0 && capture.Process?.privateBytes > 0,
    'Windows working set/private memory was not measured');
  assert(capture.KernelSocketBytes === null && capture.KernelSocketMemoryNote,
    'Unavailable kernel socket memory must be labelled unknown');
  const held = heldTCP + heldUDP;
  const result = { ...capture, heldTCP, heldUDP, independentHeld: held, heapLimit,
    oldRuntimeBudgetWouldPass: capture.ManagedBytes <= 512 * 1024 * 1024,
    gcCPUppm: Math.round(capture.GCCPUSeconds / Math.max(1e-9, capture.TotalCPUSeconds) * 1e6) };
  if (baseline && held > 0) result.perFlow = {
    heapBytes: (capture.HeapAlloc - baseline.HeapAlloc) / held,
    stackBytes: (capture.StackInUse - baseline.StackInUse) / held,
    managedBytes: (capture.ManagedBytes - baseline.ManagedBytes) / held,
    gcWindowShare: (capture.GCCPUSeconds - baseline.GCCPUSeconds) /
      Math.max(1e-9, capture.TotalCPUSeconds - baseline.TotalCPUSeconds),
  };
  console.log(`WINDOWS HELD HEAP CAPTURE ${JSON.stringify(result)}`);
  assert(capture.HeapAlloc <= heapLimit, `Post-GC live heap exceeded the 90% headroom gate: ${JSON.stringify(result)}`);
  return result;
}
