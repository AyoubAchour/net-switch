import assert from 'node:assert/strict';
import { once } from 'node:events';
import path from 'node:path';
import { test } from 'node:test';
import { killTree, runPowerShell, runPowerShellJson, spawnPowerShell, SYSTEM32 } from '../lib/ps.mjs';

const windows = { skip: process.platform !== 'win32' };

test('a hanging PowerShell rejects promptly with the timeout error shape', windows, async () => {
  const start = Date.now();
  await assert.rejects(runPowerShell('Start-Sleep 30', { timeoutMs: 1500 }), (error) => {
    assert.equal(error.killed, true);
    assert.equal(typeof error.stderr, 'string');
    return true;
  });
  assert.ok(Date.now() - start < 10_000);
});

test('a timeout also stops the child PowerShell started', windows, async (t) => {
  let childPid;
  t.after(() => killTree(childPid));
  const start = Date.now();
  // Leave room for PowerShell startup when tests run at low priority. The
  // child must exist before this case can test descendant cleanup.
  await assert.rejects(runPowerShell(String.raw`
$info = New-Object System.Diagnostics.ProcessStartInfo
$info.FileName = "$env:SystemRoot\System32\ping.exe"
$info.Arguments = '-n 30 127.0.0.1'
$info.UseShellExecute = $false
$info.CreateNoWindow = $true
$child = [System.Diagnostics.Process]::Start($info)
[Console]::WriteLine("CHILD=$($child.Id)")
[Console]::Out.Flush()
Start-Sleep 30
`, { timeoutMs: 10_000 }), (error) => {
    const match = error.stdout.match(/CHILD=(\d+)/);
    assert.ok(match, `the child was started before the timeout: ${error.stderr}`);
    childPid = Number(match[1]);
    assert.equal(error.killed, true);
    return true;
  });
  assert.ok(Date.now() - start < 20_000);
  assert.throws(() => process.kill(childPid, 0), { code: 'ESRCH' });
});

test('nonzero exits preserve their code and stderr', windows, async () => {
  await assert.rejects(runPowerShell('[Console]::Error.WriteLine("failure"); exit 7'), (error) => {
    assert.equal(error.code, 7);
    assert.match(error.stderr, /failure/);
    return true;
  });
});

test('both PowerShell helpers restrict modules and strip Node options while preserving arguments', windows, async (t) => {
  const beforeModules = process.env.PSModulePath;
  const beforeOptions = process.env.NODE_OPTIONS;
  t.after(() => {
    if (beforeModules === undefined) delete process.env.PSModulePath;
    else process.env.PSModulePath = beforeModules;
    if (beforeOptions === undefined) delete process.env.NODE_OPTIONS;
    else process.env.NODE_OPTIONS = beforeOptions;
  });
  process.env.PSModulePath = 'C:\\untrusted-modules';
  process.env.NODE_OPTIONS = '--inspect';
  const script = '[pscustomobject]@{ modules = $env:PSModulePath; options = $env:NODE_OPTIONS; value = $env:NETSWITCH_VALUE } | ConvertTo-Json -Compress';
  const value = 'quotes " curly ’ $()';
  const expectedModules = [path.join(SYSTEM32, 'WindowsPowerShell', 'v1.0', 'Modules'), path.join(process.env.ProgramFiles ?? 'C:\\Program Files', 'WindowsPowerShell', 'Modules')];
  const check = (result) => {
    assert.deepEqual(result.modules.split(';'), expectedModules);
    assert.equal(result.options, null);
    assert.equal(result.value, value);
  };
  check(await runPowerShellJson(script, { args: { VALUE: value } }));
  const child = spawnPowerShell(script, { args: { VALUE: value } });
  t.after(() => killTree(child.pid));
  let output = '';
  child.stdout.setEncoding('utf8').on('data', (chunk) => { output += chunk; });
  const [code] = await once(child, 'close');
  assert.equal(code, 0);
  check(JSON.parse(output));
});

test('killTree ignores invalid and already absent process IDs', async () => {
  await killTree(undefined);
  await killTree(-1);
  await killTree(0);
  await killTree(2147483647);
});
