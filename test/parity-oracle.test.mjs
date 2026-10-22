import assert from 'node:assert/strict';
import test from 'node:test';
import { ORACLE_TIMEOUT_MS, oraclePowerShellJson, oracleRead } from '../tests/windows/parity-oracle.mjs';

const clock = (...times) => {
  let next = 0;
  return () => times[next++];
};

test('a killed oracle names the command, its deadline and the wait', async () => {
  let passed;
  const run = async (_script, options) => {
    passed = options;
    throw Object.assign(new Error('PowerShell did not answer.'), { killed: true });
  };
  await assert.rejects(
    oraclePowerShellJson('script', { command: 'windows.detectAdapters', args: { ALIAS: 'Ethernet' }, run, now: clock(1_000, 91_250) }),
    { message: 'windows.detectAdapters: timed out after 90000 ms (waited 90250 ms).' },
  );
  assert.equal(passed.timeoutMs, ORACLE_TIMEOUT_MS);
  assert.deepEqual(passed.args, { ALIAS: 'Ethernet' });
});

test('another oracle failure keeps the first stderr line, not the encoded command', async () => {
  const error = Object.assign(new Error('Command failed: powershell.exe -EncodedCommand AAAA'), {
    code: 7,
    stderr: 'Get-NetIPInterface : Access is denied.\r\nAt line:1 char:1\r\n',
  });
  await assert.rejects(
    oraclePowerShellJson('script', { command: 'readMetrics', run: async () => { throw error; }, now: clock(0, 25) }),
    { message: 'readMetrics: failed after 25 ms: Get-NetIPInterface : Access is denied.' },
  );
});

test('a reader with a shipped deadline reports that deadline', async () => {
  const error = Object.assign(new Error('PowerShell did not answer.'), { killed: true });
  await assert.rejects(
    oracleRead('windows.readMinimizeConnectionsPolicy', async () => { throw error; }, { timeoutMs: 10_000, now: clock(0, 10_040) }),
    { message: 'windows.readMinimizeConnectionsPolicy: timed out after 10000 ms (waited 10040 ms).' },
  );
});
