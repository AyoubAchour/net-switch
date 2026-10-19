import { spawnPowerShell, killTree } from '../lib/ps.mjs';
import { ADAPTERS_SCRIPT } from '../lib/platform/windows-network.mjs';

// Temporary CI probe: the same scan, with markers around each blocking phase.
export async function timedScan() {
  const started = performance.now();
  const mark = (name) => `[Console]::Error.WriteLine('SCAN ${name}')\n`;
  let script = mark('script-entry') + ADAPTERS_SCRIPT;
  for (const [needle, name] of [
    ['$interfaces =', 'routes-done'], ['$addresses =', 'interfaces-done'],
    ['$ssids =', 'addresses-done'], ['$list =', 'netsh-done'],
    ['  $interface =', 'adapter-query-done'], ['ConvertTo-Json -InputObject', 'projection-done'],
  ]) script = script.replace(needle, mark(name) + needle);
  script += mark('json-done');
  const child = spawnPowerShell(script);
  let stdout = '', stderr = '';
  const log = (phase) => console.log(`SCAN TIMING ${JSON.stringify({ arch: process.arch, phase, ms: performance.now() - started })}`);
  log('spawn');
  child.stdout.on('data', (chunk) => { log('stdout'); stdout += chunk; });
  child.stderr.on('data', (chunk) => { log(String(chunk)); stderr += chunk; });
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => { log('deadline-30000'); void killTree(child.pid); }, 30_000);
    child.once('error', (error) => { clearTimeout(timer); reject(error); });
    child.once('close', (code) => {
      clearTimeout(timer); log(`exit-${code}`);
      if (code !== 0) reject(new Error(`Scan failed: ${stderr}`));
      else resolve(JSON.parse(stdout));
    });
  });
}
