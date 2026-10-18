import { appendFileSync } from 'node:fs';
import path from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import * as network from './windows-network.mjs';
import * as autostart from '../autostart.mjs';
import { AppInfo } from '../appinfo.mjs';
import { InstalledApps } from '../installed-apps.mjs';
import { describeFailure } from '../network.mjs';
import { killTree, runFile, runPowerShell, SYSTEM32 } from '../ps.mjs';
import { openUndoRecord, undoWindowsChanges } from '../windows-undo.mjs';
import { windowsAppPath } from './windows-paths.mjs';

export const windows = {
  ...network,
  ...autostart,
  createAppInfo: (options) => new AppInfo(options),
  createInstalledApps: (options) => new InstalledApps(options),
  openUndoRecord,
  undoWindowsChanges,
  protectMachineDir,
  portHolder,
  killTree,
  stopOrphan,
  engineFileName: 'sing-box.exe',
  helperFileName: 'netswitch-helper.exe',
  requiredEngineFiles: (arch) => arch === 'arm64' ? [] : ['libcronet.dll'],
  noAppPath: 'C:\\NetSwitch\\no-app-selected.exe',
  tunOptions: () => ({}),
  updateAssetName: (version, arch) => `NetSwitch-Setup-${version}-${arch}.exe`,
  appPath: windowsAppPath,
};

// The machine folder holds the undo record and what the engine runs from, so
// only administrators and the system may read or change it. Anyone can create
// folders in %ProgramData%, so the folder may already exist with other owners
// or permissions: it gets a fresh owner and an exact list of who may use it,
// its contents inherit that, and the result is checked. Accounts are named by
// well-known SIDs, which read the same in any Windows language.
const PROTECT_SCRIPT = `
$ErrorActionPreference = 'Stop'
$dir = $env:NETSWITCH_DIR
$admins = New-Object System.Security.Principal.SecurityIdentifier 'S-1-5-32-544'
$system = New-Object System.Security.Principal.SecurityIdentifier 'S-1-5-18'
function Assert-NotLink($item) {
  if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw "$($item.FullName) is a link, which Net Switch won't follow" }
}
Assert-NotLink (Get-Item -LiteralPath $dir -Force)
$acl = New-Object System.Security.AccessControl.DirectorySecurity
$acl.SetOwner($admins)
$acl.SetAccessRuleProtection($true, $false)
foreach ($sid in $admins, $system) {
  $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($sid, 'FullControl', 'ContainerInherit, ObjectInherit', 'None', 'Allow')))
}
Set-Acl -LiteralPath $dir -AclObject $acl
foreach ($item in @(Get-ChildItem -LiteralPath $dir -Recurse -Force)) {
  Assert-NotLink $item
  $child = Get-Acl -LiteralPath $item.FullName
  $child.SetOwner($admins)
  $child.SetAccessRuleProtection($false, $false)
  foreach ($rule in @($child.Access | Where-Object { -not $_.IsInherited })) { [void]$child.RemoveAccessRuleSpecific($rule) }
  Set-Acl -LiteralPath $item.FullName -AclObject $child
}
$check = Get-Acl -LiteralPath $dir
if (-not $check.AreAccessRulesProtected) { throw 'the folder still inherits permissions' }
$allowed = @('S-1-5-32-544', 'S-1-5-18')
$others = @($check.Access | ForEach-Object { $_.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value } | Where-Object { $allowed -notcontains $_ })
if ($others.Count -gt 0) { throw "others still have access: $($others -join ', ')" }
'protected'
`;

export async function protectMachineDir(dir, logPath) {
  try {
    const output = await runPowerShell(PROTECT_SCRIPT, { timeoutMs: 30_000, args: { DIR: dir } });
    if (!output.includes('protected')) throw new Error('the permission check did not complete');
  } catch (error) {
    // The folder feeds a program that runs as administrator, so Net Switch
    // doesn't start without it locked down. launch.ps1 points to this log.
    const reason = describeFailure(error, 30_000);
    appendFileSync(
      logPath,
      `${new Date().toISOString()} Net Switch can't start: ${dir} couldn't be limited to administrators (${reason}). Make sure it is a normal folder, not a link, then start Net Switch again. Don't delete it: it holds the record Undo needs to restore your Windows settings.\n`,
    );
    process.exit(1);
  }
}

// The program holding a local port, from netstat and tasklist (no WMI, which
// can hang). Rows are matched by their numbers, so this reads the same in any
// Windows language. Null when it can't be told.
export async function portHolder(port) {
  try {
    const table = await runFile(path.join(SYSTEM32, 'NETSTAT.EXE'), ['-ano', '-p', 'TCP'], { timeoutMs: 10_000 });
    const row = new RegExp(String.raw`^\s*TCP\s+127\.0\.0\.1:${port}\s+0\.0\.0\.0:0\s+\S+\s+(\d+)\s*$`, 'm').exec(table);
    if (!row) return null;
    const pid = Number(row[1]);
    const list = await runFile(path.join(SYSTEM32, 'tasklist.exe'), ['/FI', `PID eq ${pid}`, '/FO', 'CSV', '/NH'], {
      timeoutMs: 10_000,
    });
    const image = /^"([^"]+)"/.exec(list.trim())?.[1];
    return image ? { pid, image: image.toLowerCase() } : null;
  } catch {
    return null;
  }
}

export async function stopOrphan(pid, singBoxPath) {
  // When the PID is gone, Get-Process still records an error that makes
  // PowerShell exit with code 1, so the script ends with an explicit exit 0.
  // A failed Stop-Process still stops the script before it gets there.
  let output;
  try {
    output = await runPowerShell(
      `$p = Get-Process -Id ${pid} -ErrorAction SilentlyContinue
if ($p -and $p.Path -eq $env:NETSWITCH_EXE) { Stop-Process -Id ${pid} -Force -ErrorAction Stop; 'stopped' }
exit 0`,
      { args: { EXE: singBoxPath } },
    );
  } catch (error) {
    throw new Error("Couldn't check whether the routing engine from an earlier run is still running.", {
      cause: error,
    });
  }
  if (output.includes('stopped')) await delay(1000);
}
