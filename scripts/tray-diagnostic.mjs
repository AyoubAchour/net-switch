import { spawnSync } from 'node:child_process';
import os from 'node:os';

if (!process.env.GITHUB_ACTIONS || process.platform !== 'win32') throw new Error('CI only');
console.log(JSON.stringify({ arch: process.arch, cpus: os.availableParallelism(), node: process.version }));
const results = [];
for (let round = 1; round <= 3; round++) {
  for (const mode of ['suite', 'native']) {
    console.log(`ROUND ${round} MODE ${mode} ${new Date().toISOString()}`);
    const build = spawnSync('powershell.exe', ['-NoProfile', '-File', mode === 'native' ? 'scripts/build-tray-native-diagnostic.ps1' : 'scripts/build-tray.ps1'], { stdio: 'inherit' });
    if (build.status !== 0) process.exit(1);
    const inventory = spawnSync('powershell.exe', ['-NoProfile', '-Command', 'Get-Process NetSwitchTray,MsMpEng,mscorsvw -ErrorAction SilentlyContinue | Select-Object Id,ProcessName,CPU,StartTime | Format-Table; Get-MpComputerStatus | Select-Object AMProductVersion,AntivirusSignatureVersion,RealTimeProtectionEnabled | Format-List'], { stdio: 'inherit' });
    const start = performance.now();
    const trace = `tray/bin/trace-${round}-${mode}.etl`;
    const traceStart = spawnSync('logman.exe', ['start', 'NetSwitchTrayDiagnostic', '-p', 'Microsoft-Windows-DotNETRuntime', '0x18', '5', '-o', trace, '-ets'], { stdio: 'inherit' });
    const run = spawnSync(process.execPath, ['--test', '--test-reporter=tap', 'test/*.test.mjs'], { stdio: 'inherit', env: { ...process.env, NETSWITCH_TRAY_DIAGNOSTIC: '1' }, timeout: 180_000 });
    const result = { round, mode, status: run.status, signal: run.signal, elapsed: Math.round(performance.now() - start) };
    results.push(result);
    console.log('RESULT ' + JSON.stringify(result));
    if (traceStart.status === 0) {
      spawnSync('logman.exe', ['stop', 'NetSwitchTrayDiagnostic', '-ets'], { stdio: 'inherit' });
      spawnSync('powershell.exe', ['-NoProfile', '-File', 'scripts/read-tray-trace.ps1', '-Trace', trace], { stdio: 'inherit' });
    }
  }
}
console.log('SUMMARY ' + JSON.stringify(results));
