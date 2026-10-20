// Read live evidence before the harness stops Control or the engine. Probes
// are independent: a stuck Control API must not hide a responsive engine API.
import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { hostedOnly, run } from '../tests/windows/testisp/harness.mjs';

export async function probe(label, url, headers, log) {
  const started = performance.now();
  const at = new Date().toISOString();
  let result;
  try {
    const response = await fetch(url, { headers, signal: AbortSignal.timeout(2500) });
    const value = await response.json();
    result = { outcome: response.ok ? 'answered' : 'HTTP error', status: response.status,
      value: label === 'Control /state' ? { routing: value.routing } : value };
  } catch (error) {
    const code = error.cause?.code ?? error.code;
    result = { outcome: error.name === 'TimeoutError' || code === 'ETIMEDOUT' ? 'timed out'
      : code === 'ECONNREFUSED' ? 'refused' : 'failed', code, error: error.message };
  }
  log(`Live ${label}: ${JSON.stringify({ at, ms: Math.round(performance.now() - started), ...result })}`);
}

export async function diagnoseControl(engine, clientPid, responder, log) {
  hostedOnly();
  const pidText = await readFile(path.join(engine.dir, 'engine.pid'), 'utf8').catch((error) => error.code);
  const enginePid = /^\d+$/.test(pidText.trim()) ? Number(pidText.trim()) : 0;
  log(`PID file at failure: ${JSON.stringify({ value: pidText, enginePid, clientPid })}`);
  const tasks = [];
  if (engine.session) {
    tasks.push(probe('Control /state', `http://127.0.0.1:${engine.session.port}/api/state`,
      { 'X-Token': engine.session.token }, log));
  } else log('Live Control /state: no session was established');
  tasks.push((async () => {
    // Read the current config, not the adapter's cached successful-start copy.
    const config = JSON.parse(await readFile(path.join(engine.dir, 'engine-config.json'), 'utf8'));
    const { external_controller: address, secret } = config.experimental.clash_api;
    await Promise.all(['/version', '/connections'].map((route) =>
      probe(`engine ${route}`, `http://${address}${route}`, { Authorization: `Bearer ${secret}` }, log)));
  })().catch((error) => log(`Live engine probes unavailable: ${error.message}`)));
  tasks.push(run('powershell.exe', ['-NoProfile', '-ExecutionPolicy', 'Bypass', '-File',
    path.resolve('scripts/tun-test-diagnostics.ps1'), '-EnginePid', String(enginePid),
    '-ClientPid', String(clientPid), '-ResponderAddress', responder?.address ?? '',
    '-ResponderPort', String(responder?.port ?? 0)], { timeout: 45_000, env: { PSModulePath: undefined } })
    .then(({ stdout }) => log(stdout), (error) => log(`Windows diagnostics failed (partial output included): ${error.message}`)));
  await Promise.all(tasks);
}
