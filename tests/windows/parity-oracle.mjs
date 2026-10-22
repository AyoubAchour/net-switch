import { runPowerShellJson } from '../../lib/ps.mjs';

// The Win32 parity suite compares the Go worker with the old app's own readers
// ("the oracle"). Those readers run Windows PowerShell 5.1 with the deadlines
// the shipped app uses (10-30 s). A fresh windows-11-arm runner can spend
// longer than that preparing PowerShell and the NetTCPIP/CIM providers: the
// first adapter scan was killed at 20 s in run 39812909525, while the next
// PowerShell start took 1.2 s. Oracle commands in the harness therefore get a
// deadline that fits the runner. lib/ keeps the deadlines a real PC meets.
export const ORACLE_TIMEOUT_MS = 90_000;

// The deadline inside a shipped reader whose call path takes no timeout. It is
// stated here only so a timeout can name it; the reader still owns its timer.
export const SHIPPED_TIMEOUT_MS = 20_000;

// The first useful line of a failure. PowerShell writes its diagnostics to
// stderr, but a killed child leaves only a CLIXML blob there, and execFile
// prefixes its own message with the whole encoded command.
function detail(error) {
  const lines = String(error?.stderr ?? '')
    .replace(/#< CLIXML[\s\S]*$/, '')
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean);
  if (lines.length > 0) return lines[0].slice(0, 160);
  const message = String(error?.message ?? '');
  return message.startsWith('Command failed:') ? `PowerShell exited with code ${error?.code ?? 'unknown'}` : message.slice(0, 160);
}

function explain(command, error, timeoutMs, elapsedMs) {
  if (error?.killed) return new Error(`${command}: timed out after ${timeoutMs} ms (waited ${elapsedMs} ms).`, { cause: error });
  return new Error(`${command}: failed after ${elapsedMs} ms: ${detail(error)}`, { cause: error });
}

// Runs an oracle script with the harness deadline. `run` and `now` are
// injectable so the timeout plumbing has a unit test that starts no process.
export async function oraclePowerShellJson(script, { command, args = {}, timeoutMs = ORACLE_TIMEOUT_MS, run = runPowerShellJson, now = Date.now } = {}) {
  const started = now();
  try {
    return await run(script, { timeoutMs, args });
  } catch (error) {
    throw explain(command, error, timeoutMs, Math.round(now() - started));
  }
}

// Wraps a reader that owns its timer, so a kill says which read gave up instead
// of surfacing "Command failed" and a CLIXML blob.
export async function oracleRead(command, read, { timeoutMs = SHIPPED_TIMEOUT_MS, now = Date.now } = {}) {
  const started = now();
  try {
    return await read();
  } catch (error) {
    throw explain(command, error, timeoutMs, Math.round(now() - started));
  }
}
