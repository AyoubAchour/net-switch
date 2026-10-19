// Destructive probes are confined to disposable GitHub-hosted Windows runners.
// Each case compares the old implementation with the Go worker, not a handwritten
// expected value. Temporary settings and connections are restored in finally.
import assert from 'node:assert/strict';
import { execFile, spawn } from 'node:child_process';
import { mkdtemp, mkdir, rm, writeFile, readFile, realpath, symlink } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { createServer, connect } from 'node:net';
import { promisify } from 'node:util';
import { once } from 'node:events';
import { windows } from '../lib/platform/windows.mjs';
import { nativeArchitecture } from '../lib/architecture.mjs';
import { AppInfo } from '../lib/appinfo.mjs';
import { appKey } from '../lib/apps.mjs';
import { InstalledApps } from '../lib/installed-apps.mjs';
import { restoreMetrics, restoreMinimizeConnectionsPolicy } from '../lib/platform/windows-network.mjs';
import { runPowerShellJson } from '../lib/ps.mjs';
import { recordExecutable } from './server-under-test.mjs';

if (process.platform !== 'win32' || process.env.GITHUB_ACTIONS !== 'true' || process.env.RUNNER_ENVIRONMENT !== 'github-hosted') {
  throw new Error('Win32 parity may run only on disposable GitHub-hosted Windows runners.');
}
const executable = path.resolve(process.argv[2]);
await recordExecutable('WIN32 IMPLEMENTATION UNDER TEST', executable);
const run = promisify(execFile);
const native = async (name, args = {}) => {
  const payload = Buffer.from(JSON.stringify(args)).toString('base64url');
  const { stdout } = await run(executable, ['worker', 'query', name, payload], { windowsHide: true, timeout: 45_000, maxBuffer: 8 * 1024 * 1024 });
  const value = JSON.parse(stdout);
  if (value.error) throw new Error(`${name}: ${value.error}`);
  return value.value;
};
let count = 0;
let failures = 0;
async function check(name, fn) {
  count++;
  try { await fn(); console.log(`ok ${count} - ${name}`); }
  catch (error) { failures++; console.error(`not ok ${count} - ${name}\n${error.stack}`); }
}
const folder = await mkdtemp(path.join(tmpdir(), 'netswitch-win32-parity-'));
try {
  await check('elevation and native architecture', async () => {
    assert.equal(await native('elevated'), await windows.isElevated());
    assert.equal(await native('architecture'), nativeArchitecture());
  });
  let adapters;
  await check('adapter fields and default routes', async () => {
    adapters = await windows.detectAdapters();
    const current = await native('network');
    for (const previous of adapters) {
      const actual = current.adapters.find((a) => a.alias === previous.alias);
      assert(actual, `missing adapter ${previous.alias}`);
      for (const key of ['index', 'description', 'status', 'mediaType', 'linkSpeed', 'virtual', 'ipv4', 'metric', 'automaticMetric', 'ssid']) assert.deepEqual(actual[key], previous[key], `${previous.alias}.${key}`);
      assert.equal(actual.guid.replace(/[{}]/g, '').toLowerCase(), previous.guid.replace(/[{}]/g, '').toLowerCase());
      assert.deepEqual([...actual.ipv4s].sort(), [...previous.ipv4s].sort());
    }
    const before = await windows.readDefaultRoutes();
    for (const route of before) assert(current.defaultRoutes.some((r) => r.gateway === route.gateway && r.interfaceAddress === route.interfaceAddress), JSON.stringify(route));
  });
  await check('Wi-Fi policy registry read, write and restore', async () => {
    const before = await windows.readMinimizeConnectionsPolicy();
    assert.equal(await native('policy'), before);
    try {
      await native('policy-set', { value: 0 });
      assert.equal(await windows.readMinimizeConnectionsPolicy(), 0);
      await native('policy-set', { value: before });
      assert.equal(await windows.readMinimizeConnectionsPolicy(), before);
    } finally { await restoreMinimizeConnectionsPolicy(before); }
  });
  await check('metrics, active writes, persistent writes and restore', async () => {
    const adapter = adapters.find((a) => a.connected);
    assert(adapter, 'runner needs a connected adapter');
    const before = await windows.readMetrics(adapter.alias);
    assert.deepEqual(await native('metrics', { alias: adapter.alias }), before);
    try {
      await native('metrics-set', { alias: adapter.alias, before, metric: 123 });
      const active = await windows.readMetrics(adapter.alias);
      assert(active.every((r) => r.metric === 123 && r.automatic === false));
      const persistent = await runPowerShellJson(`$items = Get-NetIPInterface -InterfaceAlias $env:NETSWITCH_ALIAS -PolicyStore PersistentStore -ErrorAction Stop
ConvertTo-Json -InputObject @($items | ForEach-Object { [pscustomobject]@{ family=[string]$_.AddressFamily; metric=[int]$_.InterfaceMetric; automatic=([string]$_.AutomaticMetric -eq 'Enabled') } }) -Compress`, { args: { ALIAS: adapter.alias } });
      assert.equal(persistent.length, before.length);
      assert(persistent.every((r) => r.metric === 123 && r.automatic === false), JSON.stringify(persistent));
      await native('metrics-restore', { alias: adapter.alias, metrics: before });
      assert.deepEqual(await windows.readMetrics(adapter.alias), before);
    } finally { await restoreMetrics(adapter.alias, before); }
  });
  await check('machine folder ACL SDDL and inherited child ACLs', async () => {
    const old = path.join(folder, 'old'), current = path.join(folder, 'new');
    for (const p of [old, current]) { await mkdir(path.join(p, 'child'), { recursive: true }); await writeFile(path.join(p, 'child', 'record'), 'probe'); }
    await windows.protectMachineDir(old, path.join(folder, 'acl.log'));
    await native('protect-directory', { path: current });
    const sddl = async (dir) => runPowerShellJson(`ConvertTo-Json -InputObject @((Get-Acl -LiteralPath $env:NETSWITCH_DIR).Sddl, (Get-Acl -LiteralPath (Join-Path $env:NETSWITCH_DIR 'child')).Sddl, (Get-Acl -LiteralPath (Join-Path $env:NETSWITCH_DIR 'child\\record')).Sddl) -Compress`, { args: { DIR: dir } });
    assert.deepEqual(await sddl(current), await sddl(old));
  });
  await check('Start-menu resolved app list', async () => {
    const before = await new InstalledApps().list();
    const current = (await native('installed-apps')).map(({ name, path }) => ({ name, path }));
    const ordered = (items) => items.sort((a, b) => a.path.localeCompare(b.path));
    assert.deepEqual(ordered(current), ordered(before));
  });
  await check('version names and icon pixels', async () => {
    const paths = [process.execPath, path.join(process.env.SystemRoot, 'System32', 'notepad.exe')];
    const info = new AppInfo(); paths.forEach((p) => info.describe(p)); await info.lookupPending();
    const current = await native('app-info', { paths });
    for (const item of current) {
      const old = info.cache.get(appKey(item.path));
      assert.equal(item.name, old.name, item.path);
      assert.equal(Boolean(item.icon), Boolean(old.icon));
      if (!item.icon) continue;
      const pixels = await runPowerShellJson(`Add-Type -AssemblyName System.Drawing
$result = foreach ($text in @($env:NETSWITCH_OLD, $env:NETSWITCH_NEW)) {
  $stream = New-Object IO.MemoryStream(,[Convert]::FromBase64String($text))
  $bitmap = New-Object Drawing.Bitmap($stream)
  $all = New-Object 'System.Collections.Generic.List[int]'
  for ($y=0; $y -lt $bitmap.Height; $y++) { for ($x=0; $x -lt $bitmap.Width; $x++) { $all.Add($bitmap.GetPixel($x,$y).ToArgb()) } }
  [pscustomobject]@{ width=$bitmap.Width; height=$bitmap.Height; pixels=$all.ToArray() }
  $bitmap.Dispose(); $stream.Dispose()
}
ConvertTo-Json -InputObject @($result) -Compress -Depth 4`, { args: { OLD: old.icon, NEW: item.icon } });
      assert.deepEqual(pixels[1], pixels[0], item.path);
    }
  });
  await check('port holder and TCP close with stale-owner rejection', async () => {
    const listener = createServer(); listener.listen(0, '127.0.0.1'); await once(listener, 'listening');
    let client, accepted;
    try {
      const port = listener.address().port;
      const [expected, actual] = await Promise.all([windows.portHolder(port), native('port-holder', { port })]);
      assert.deepEqual(actual, expected);
      const connected = once(listener, 'connection'); client = connect(port, '127.0.0.1'); [accepted] = await connected; accepted.on('error', () => {}); client.on('error', () => {}); await once(client, 'connect');
      const tuple = await runPowerShellJson(`$c = Get-NetTCPConnection -LocalPort $env:NETSWITCH_PORT -RemotePort $env:NETSWITCH_REMOTE -State Established -ErrorAction Stop | Select-Object -First 1
[pscustomobject]@{ local=[string]$c.LocalAddress; lport=[int]$c.LocalPort; remote=[string]$c.RemoteAddress; rport=[int]$c.RemotePort; pid=[int]$c.OwningProcess; created=$c.CreationTime.ToUniversalTime().ToString('o') } | ConvertTo-Json -Compress`, { args: { PORT: client.localPort, REMOTE: port } });
      assert.equal((await native('close-tcp', { connections: [{ ...tuple, pid: tuple.pid + 1000000 }] })).gone, 1);
      const [precise] = await native('tcp-identity', { port: client.localPort });
      console.log(`TCP identity parity: ${JSON.stringify({ powerShell: tuple, native: precise })}`);
      for (const key of ['local', 'lport', 'remote', 'rport', 'pid']) assert.equal(precise[key], tuple[key]);
      // The CIM provider truncates CreationTime to whole seconds on Windows.
      // Each implementation must use the identity its own reader supplied;
      // accepting a coarse timestamp in native close could hit a reused socket.
      assert.equal(precise.created.slice(0, 19), tuple.created.slice(0, 19));
      assert.equal((await native('close-tcp', { connections: [{ ...precise, processStarted: '1900-01-01T00:00:00.0000000Z' }] })).gone, 1);
      const closed = new Promise((resolve) => client.once('close', resolve));
      const nativeResult = await native('close-tcp', { connections: [precise] });
      assert.deepEqual(nativeResult, { closed: 1, failed: 0, gone: 0, codes: [] });
      await closed;
      assert.equal((await windows.closeTcpConnections([tuple])).gone, 1);
      accepted.destroy();
      const connectedAgain = once(listener, 'connection'); client = connect(port, '127.0.0.1'); [accepted] = await connectedAgain; accepted.on('error', () => {}); client.on('error', () => {}); await once(client, 'connect');
      const oldTuple = await runPowerShellJson(`$c = Get-NetTCPConnection -LocalPort $env:NETSWITCH_PORT -RemotePort $env:NETSWITCH_REMOTE -State Established -ErrorAction Stop | Select-Object -First 1
[pscustomobject]@{ local=[string]$c.LocalAddress; lport=[int]$c.LocalPort; remote=[string]$c.RemoteAddress; rport=[int]$c.RemotePort; pid=[int]$c.OwningProcess; created=$c.CreationTime.ToUniversalTime().ToString('o') } | ConvertTo-Json -Compress`, { args: { PORT: client.localPort, REMOTE: port } });
      const oldClosed = new Promise((resolve) => client.once('close', resolve));
      assert.deepEqual(await windows.closeTcpConnections([oldTuple]), nativeResult);
      await oldClosed;
    } finally { client?.destroy(); accepted?.destroy(); await new Promise((resolve) => listener.close(resolve)); }
  });
  await check('Task Scheduler registration, read and removal', async () => {
    const args = { on: true, executable, root: path.dirname(executable), userDir: folder, machineDir: folder };
    try {
      await native('autostart-set', args);
      assert.equal(await native('autostart'), true);
      assert.equal(await windows.readAutostart(), true);
      const settings = await runPowerShellJson(`$service=New-Object -ComObject Schedule.Service; $service.Connect(); $folder=$service.GetFolder('\\Net Switch')
$result=foreach($name in 'Server','Sign-in') { $task=$folder.GetTask($name); [xml]$xml=$task.Xml; [pscustomobject]@{ name=$name; logon=[string]$xml.Task.Principals.Principal.LogonType; level=[string]$xml.Task.Principals.Principal.RunLevel; priority=[string]$xml.Task.Settings.Priority; limit=[string]$xml.Task.Settings.ExecutionTimeLimit; battery=[string]$xml.Task.Settings.DisallowStartIfOnBatteries; multiple=[string]$xml.Task.Settings.MultipleInstancesPolicy } }
ConvertTo-Json -InputObject @($result) -Compress`);
      assert.deepEqual(settings.map((s) => s.level), ['HighestAvailable', 'LeastPrivilege']);
      assert(settings.every((s) => s.logon === 'InteractiveToken' && s.priority === '4' && s.limit === 'PT0S' && s.battery === 'false' && s.multiple === 'IgnoreNew'));
    } finally { await native('autostart-set', { on: false }); }
    assert.equal(await native('autostart'), false);
    assert.equal(await windows.readAutostart(), false);
  });
  await check('reparse-point rejection leaves the target ACL unchanged', async () => {
    const target = path.join(folder, 'link-target'), link = path.join(folder, 'root-link');
    const parent = path.join(folder, 'linked-child');
    await mkdir(target); await mkdir(parent); await symlink(target, link, 'junction');
    await symlink(target, path.join(parent, 'nested-link'), 'junction');
    const acl = () => runPowerShellJson(`(Get-Acl -LiteralPath $env:NETSWITCH_DIR).Sddl | ConvertTo-Json -Compress`, { args: { DIR: target } });
    const before = await acl();
    await assert.rejects(native('protect-directory', { path: link }), /reparse point/i);
    await assert.rejects(native('protect-directory', { path: parent }), /reparse point/i);
    assert.equal(await acl(), before);
  });
  await check('process identity is checked before stopping a child', async () => {
    const image = await realpath(process.execPath);
    for (const stop of [windows.stopOrphan, (pid, image) => native('stop-process', { pid, path: image })]) {
      const child = spawn(image, ['-e', 'process.stdout.write("ready\\n");setInterval(()=>{},1000)'], { windowsHide: true, stdio: ['ignore', 'pipe', 'pipe'] });
      try {
        await once(child.stdout, 'data');
        await stop(child.pid, path.join(folder, 'not-the-owned-process.exe'));
        assert.equal(child.exitCode, null, 'a mismatched image was stopped');
        const exited = once(child, 'exit');
        await stop(child.pid, image);
        await exited;
        assert.notEqual(child.exitCode, null, 'the matching child did not exit');
      } finally { if (child.exitCode === null) child.kill(); }
    }
  });
  console.log(`Win32 parity: ${count} cases executed, ${count - failures} passed, ${failures} failed`);
  if (failures) process.exitCode = 1;
} finally { await rm(folder, { recursive: true, force: true }); }
