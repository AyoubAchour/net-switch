// Starting with Windows, through two scheduled tasks in a "Net Switch" folder:
// - Server starts the routing service as administrator, on request only.
//   Windows lets a task do that without asking each time, because an
//   administrator created it; launch.ps1 runs it instead of asking for
//   permission, so opening Net Switch never shows a prompt while this is on.
//   It runs node.exe through the windowless helper: node.exe is a console
//   program, and started by the task directly it opens a console window.
// - Sign-in runs launch.ps1 -Background as the person when they sign in: it
//   runs Server, then the tray icon, and opens no window.
// Only an installed copy can do this: the task runs its files as
// administrator without asking, so they must be in a folder only
// administrators can change (Program Files). A source checkout is not.
import { existsSync } from 'node:fs';
import { win32 as path } from 'node:path';
import { runFile, runPowerShell, SYSTEM32 } from './ps.mjs';

export const TASK_FOLDER = 'Net Switch';
export const SERVER_TASK = 'Server';
export const SIGN_IN_TASK = 'Sign-in';
const SCHTASKS = path.join(SYSTEM32, 'schtasks.exe');
const POWERSHELL = path.join(SYSTEM32, 'WindowsPowerShell', 'v1.0', 'powershell.exe');
// The user's SID, filled in by the registering script.
const USER = '__NETSWITCH_USER_SID__';

function xmlText(value) {
  return String(value).replace(/[&<>"']/g, (character) => `&#${character.charCodeAt(0)};`);
}

// The helper the Server task runs, in an installed copy.
export function installedHelper(root) {
  return path.join(root, 'helper', 'netswitch-helper.exe');
}

// Whether this copy may start with Windows: installed (it carries its own
// Node.js, which is what runs, and the helper that starts it) and in Program Files.
export function canAutostart({ root, nodePath, programFiles = process.env.ProgramFiles, exists = existsSync }) {
  if (!programFiles) return false;
  const inside = (file, folder) => {
    const relative = path.relative(folder, file);
    return relative !== '' && !relative.startsWith('..') && !path.isAbsolute(relative);
  };
  const bundled = path.join(root, 'runtime', 'node.exe');
  return (
    exists(bundled) &&
    exists(installedHelper(root)) &&
    path.resolve(nodePath).toLowerCase() === bundled.toLowerCase() &&
    inside(path.resolve(root).toLowerCase(), path.resolve(programFiles).toLowerCase())
  );
}

function taskXml({ description, trigger, runLevel, command, args, workingDirectory }) {
  return `<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo><Description>${xmlText(description)}</Description></RegistrationInfo>
  <Triggers>${trigger}</Triggers>
  <Principals>
    <Principal id="Person">
      <UserId>${USER}</UserId>
      <LogonType>InteractiveToken</LogonType>
      <RunLevel>${runLevel}</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <StartWhenAvailable>false</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <IdleSettings><StopOnIdleEnd>false</StopOnIdleEnd><RestartOnIdle>false</RestartOnIdle></IdleSettings>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>false</Hidden>
    <RunOnlyIfIdle>false</RunOnlyIfIdle>
    <WakeToRun>false</WakeToRun>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
    <Priority>4</Priority>
  </Settings>
  <Actions Context="Person">
    <Exec>
      <Command>${xmlText(command)}</Command>
      <Arguments>${xmlText(args)}</Arguments>
      <WorkingDirectory>${xmlText(workingDirectory)}</WorkingDirectory>
    </Exec>
  </Actions>
</Task>
`;
}

// The two task definitions. Priority 4 is Windows' normal priority: a task's
// default (7) would run the routing service below everything else. No time
// limit, and no stopping on battery, since the service runs all day.
export function taskDefinitions({ root, nodePath, helperPath = installedHelper(root), userDir, machineDir }) {
  const server = taskXml({
    description: 'Starts the Net Switch service. Net Switch runs this when you open it, so Windows doesn’t ask for permission each time.',
    trigger: '',
    runLevel: 'HighestAvailable',
    command: helperPath,
    args: `run "${nodePath}" "${path.join(root, 'server.mjs')}" --user-data "${userDir}" --machine-data "${machineDir}"`,
    workingDirectory: root,
  });
  const signIn = taskXml({
    description: 'Starts Net Switch when you sign in. Turn this off in Net Switch’s settings.',
    // A few seconds after sign-in, so the taskbar is there for the tray icon.
    trigger: `<LogonTrigger><Enabled>true</Enabled><UserId>${USER}</UserId><Delay>PT5S</Delay></LogonTrigger>`,
    runLevel: 'LeastPrivilege',
    command: POWERSHELL,
    args: `-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File "${path.join(root, 'launch.ps1')}" -Background`,
    workingDirectory: root,
  });
  return { server, signIn };
}

// Through the Task Scheduler's own interface rather than WMI, which can hang.
// The definitions arrive as environment values, never in the script text.
const REGISTER_SCRIPT = `
$ErrorActionPreference = 'Stop'
$sid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$service = New-Object -ComObject Schedule.Service
$service.Connect()
$root = $service.GetFolder('\\')
try { $folder = $root.GetFolder($env:NETSWITCH_FOLDER) } catch { $folder = $root.CreateFolder($env:NETSWITCH_FOLDER) }
# 6: create or update. 3: run with the person's own sign-in.
[void]$folder.RegisterTask($env:NETSWITCH_SERVER_NAME, $env:NETSWITCH_SERVER.Replace('${USER}', $sid), 6, $null, $null, 3)
[void]$folder.RegisterTask($env:NETSWITCH_SIGNIN_NAME, $env:NETSWITCH_SIGNIN.Replace('${USER}', $sid), 6, $null, $null, 3)
'registered'
`;

// Removes both tasks and the folder; a task or folder that is already gone is fine.
const REMOVE_SCRIPT = `
$ErrorActionPreference = 'Stop'
$service = New-Object -ComObject Schedule.Service
$service.Connect()
$root = $service.GetFolder('\\')
$folder = $null
try { $folder = $root.GetFolder($env:NETSWITCH_FOLDER) } catch {}
if ($folder) {
  foreach ($name in $env:NETSWITCH_SERVER_NAME, $env:NETSWITCH_SIGNIN_NAME) {
    try { $folder.DeleteTask($name, 0) } catch { if ($_.Exception.HResult -ne -2147024894) { throw } }
  }
  try { $root.DeleteFolder($env:NETSWITCH_FOLDER, 0) } catch {}
}
'removed'
`;

export async function enableAutostart(options) {
  const { server, signIn } = taskDefinitions(options);
  const output = await runPowerShell(REGISTER_SCRIPT, {
    timeoutMs: 30_000,
    args: { FOLDER: TASK_FOLDER, SERVER_NAME: SERVER_TASK, SIGNIN_NAME: SIGN_IN_TASK, SERVER: server, SIGNIN: signIn },
  });
  if (!output.includes('registered')) throw new Error('Windows didn’t confirm the startup task.');
}

export async function disableAutostart() {
  const output = await runPowerShell(REMOVE_SCRIPT, {
    timeoutMs: 30_000,
    args: { FOLDER: TASK_FOLDER, SERVER_NAME: SERVER_TASK, SIGNIN_NAME: SIGN_IN_TASK },
  });
  if (!output.includes('removed')) throw new Error('Windows didn’t confirm removing the startup task.');
}

// 0.3.0 registered a Server task that ran node.exe itself, which opens a
// console window on the desktop at every sign-in. This points such a task at
// the windowless helper instead, keeping its person, sign-in type and
// arguments as they are. A task this version didn't write is left alone.
// "Not found" is 0x80070002, whether the folder or the task is missing.
const UPGRADE_SCRIPT = `
$ErrorActionPreference = 'Stop'
function Test-Missing($record) {
  $exception = $record.Exception
  while ($exception) {
    if ($exception.HResult -eq -2147024894) { return $true }
    $exception = $exception.InnerException
  }
  return $false
}
$service = New-Object -ComObject Schedule.Service
$service.Connect()
$folder = $null
$task = $null
try {
  $folder = $service.GetFolder('\\').GetFolder($env:NETSWITCH_FOLDER)
  $task = $folder.GetTask($env:NETSWITCH_SERVER_NAME)
} catch {
  if (-not (Test-Missing $_)) { throw }
}
if (-not $task) { 'absent'; exit 0 }
$definition = $task.Definition
$action = $definition.Actions.Item(1)
if ($action.Path -ieq $env:NETSWITCH_HELPER) { 'current'; exit 0 }
if ($action.Path -ine $env:NETSWITCH_NODE) { 'unknown'; exit 0 }
$action.Arguments = 'run "' + $env:NETSWITCH_NODE + '" ' + $action.Arguments
$action.Path = $env:NETSWITCH_HELPER
# 4: update. Same person and sign-in type as before.
[void]$folder.RegisterTaskDefinition($env:NETSWITCH_SERVER_NAME, $definition, 4, $null, $null, $definition.Principal.LogonType)
'updated'
`;

const UPGRADE_RESULTS = ['absent', 'current', 'updated', 'unknown'];

// Returns 'absent', 'current', 'updated' or 'unknown'. Needs administrator
// rights to update. Most starts find the task current or missing, which a
// look through schtasks tells without starting PowerShell.
export async function upgradeAutostart({ nodePath, helperPath }) {
  let xml;
  try {
    xml = await runFile(SCHTASKS, ['/Query', '/TN', `\\${TASK_FOLDER}\\${SERVER_TASK}`, '/XML'], { timeoutMs: 10_000 });
  } catch (error) {
    // Exit code 1: no such task. Anything else (a timeout) says nothing.
    if (error.code === 1) return 'absent';
    throw error;
  }
  const command = /<Command>([^<]*)<\/Command>/.exec(xml)?.[1]?.trim() ?? '';
  if (command.toLowerCase() === helperPath.toLowerCase()) return 'current';
  const output = await runPowerShell(UPGRADE_SCRIPT, {
    timeoutMs: 30_000,
    args: { FOLDER: TASK_FOLDER, SERVER_NAME: SERVER_TASK, NODE: nodePath, HELPER: helperPath },
  });
  const result = output.trim().split(/\r?\n/).pop()?.trim();
  if (!UPGRADE_RESULTS.includes(result)) throw new Error(`Windows didn’t confirm updating the startup task (${output.trim().slice(0, 80)}).`);
  return result;
}

// Whether Net Switch starts with Windows: the sign-in task exists. schtasks
// answers with its exit code, which reads the same in any Windows language.
export async function readAutostart() {
  try {
    await runFile(SCHTASKS, ['/Query', '/TN', `\\${TASK_FOLDER}\\${SIGN_IN_TASK}`], { timeoutMs: 10_000 });
    return true;
  } catch (error) {
    // Exit code 1: no such task. Anything else (a timeout) says nothing.
    if (error.code === 1) return false;
    throw error;
  }
}
