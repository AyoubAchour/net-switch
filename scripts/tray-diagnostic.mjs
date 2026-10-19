import { spawnSync } from 'node:child_process';
import os from 'node:os';

if (!process.env.GITHUB_ACTIONS || process.platform !== 'win32') throw new Error('CI only');
console.log(JSON.stringify({ arch: process.arch, cpus: os.availableParallelism(), node: process.version }));
const results = [];
for (let round = 1; round <= 6; round++) {
  for (const mode of ['suite', 'alone']) {
    console.log(`ROUND ${round} MODE ${mode} ${new Date().toISOString()}`);
    const build = spawnSync('powershell.exe', ['-NoProfile', '-File', 'scripts/build-tray.ps1'], { stdio: 'inherit' });
    if (build.status !== 0) process.exit(1);
    const inventory = spawnSync('powershell.exe', ['-NoProfile', '-Command', 'Get-Process NetSwitchTray,MsMpEng,mscorsvw -ErrorAction SilentlyContinue | Select-Object Id,ProcessName,CPU,StartTime | Format-Table; Get-MpComputerStatus | Select-Object AMProductVersion,AntivirusSignatureVersion,RealTimeProtectionEnabled | Format-List'], { stdio: 'inherit' });
    const start = performance.now();
    const run = spawnSync(process.execPath, ['--test', '--test-reporter=tap', mode === 'suite' ? 'test/*.test.mjs' : 'test/tray-program.test.mjs'], { stdio: 'inherit', timeout: 180_000 });
    const result = { round, mode, status: run.status, signal: run.signal, elapsed: Math.round(performance.now() - start) };
    results.push(result);
    console.log('RESULT ' + JSON.stringify(result));
  }
}
console.log('SUMMARY ' + JSON.stringify(results));
if (results.some(result => result.status !== 0)) process.exitCode = 1;
