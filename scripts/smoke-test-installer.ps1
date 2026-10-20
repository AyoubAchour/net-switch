# Installs the built installer silently, checks the installed copy, installs it
# again over itself (the upgrade path), then uninstalls it silently and checks
# that it's gone. CI runs this on a throwaway Windows machine, as administrator.
# Don't run it on a PC where you use Net Switch.
#
#   powershell -NoProfile -ExecutionPolicy Bypass -File scripts\smoke-test-installer.ps1 -Installer dist\NetSwitch-Setup-0.1.0-x64.exe
[CmdletBinding()]
param(
  [Parameter(Mandatory = $true)] [string] $Installer,
  [ValidateSet('x64', 'arm64')] [string] $Arch = 'x64'
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
if ($env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_OS -ne 'Windows') {
  throw 'This destructive install/uninstall smoke test is only for a disposable GitHub Actions Windows runner.'
}
. (Join-Path $PSScriptRoot 'build-common.ps1')
if ((Get-NativeArchitecture) -ne $Arch) { throw "Smoke test needs a native $Arch runner." }
$installer = (Resolve-Path -LiteralPath $Installer).Path
$app = Join-Path $env:ProgramFiles 'Net Switch'
$tempRoot = if ($env:RUNNER_TEMP) { $env:RUNNER_TEMP } else { $env:TEMP }
if (-not $tempRoot) { throw 'Neither RUNNER_TEMP nor TEMP is set.' }
$logs = Join-Path $tempRoot 'net-switch-smoke'
$userData = Join-Path $env:LOCALAPPDATA 'Net Switch'
$machineData = Join-Path $env:ProgramData 'Net Switch'
$serverFile = Join-Path $userData 'server.json'
$shortcut = Join-Path ([Environment]::GetFolderPath('CommonPrograms')) 'Net Switch.lnk'
$desktopShortcut = Join-Path ([Environment]::GetFolderPath('CommonDesktopDirectory')) 'Net Switch.lnk'
$windowsPowerShell = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
foreach ($existing in @($app, $userData, $machineData, $shortcut, $desktopShortcut)) {
  if (Test-Path -LiteralPath $existing) { throw "Smoke test requires a clean runner; found $existing" }
}
New-Item -ItemType Directory -Force -Path $logs | Out-Null
$launchers = [Collections.Generic.List[object]]::new()
$browserProcesses = @{}
$launchDescendants = @{}

function Invoke-Setup([string] $Label) {
  $log = Join-Path $logs "$Label.log"
  $process = Start-Process -FilePath $installer -ArgumentList '/VERYSILENT', '/SUPPRESSMSGBOXES', '/NORESTART', '/TASKS=desktopicon', "/LOG=`"$log`"" -WindowStyle Hidden -Wait -PassThru
  if ($process.ExitCode -ne 0) {
    Get-Content -LiteralPath $log -Tail 40 -ErrorAction SilentlyContinue
    throw "$Label exited with code $($process.ExitCode)"
  }
  Write-Host "$Label succeeded"
}

function Assert-Installed {
  $expected = @(
    'launch.ps1', 'tray.ps1', 'server.mjs', 'package.json', 'LICENSE', 'THIRD_PARTY_NOTICES.md',
    'lib\engine.mjs', 'lib\tray.cs', 'ui\index.html', 'assets\net-switch.ico',
    'tools\stop.ps1', 'tools\restore-windows.mjs', 'tools\remove-autostart.mjs', 'tools\update-autostart.mjs', 'tools\netswitch-cleanup.exe',
    'runtime\node.exe', 'runtime\LICENSE',
    'engine\sing-box.exe', 'engine\SHA256SUMS.txt', 'engine\LICENSE',
    'helper\netswitch-helper.exe', 'tray\NetSwitchTray.exe',
    'licenses\GPL-3.0.txt', 'licenses\sing-box-LICENSE.txt', 'licenses\node-LICENSE.txt', 'licenses\lucide-ISC.txt',
    'licenses\cronet-go-LICENSE.txt', 'licenses\cronet-native\LICENSE', 'licenses\cronet-native\src\LICENSE',
    'licenses\wintun-LICENSE.txt', 'licenses\go-LICENSE.txt',
    'unins000.exe'
  )
  foreach ($file in $expected) {
    if (-not (Test-Path -LiteralPath (Join-Path $app $file))) { throw "Missing from the installed copy: $file" }
  }
  foreach ($unwanted in 'data', 'data-test', 'design', 'dev', 'test', '.git', 'helper\bin', 'helper\go.mod', 'tray\bin') {
    if (Test-Path -LiteralPath (Join-Path $app $unwanted)) { throw "Should not be installed: $unwanted" }
  }
  foreach ($link in @($shortcut, $desktopShortcut)) {
    if (-not (Test-Path -LiteralPath $link)) { throw "Shortcut missing: $link" }
  }
  $pins = Get-Content -LiteralPath (Join-Path $PSScriptRoot '../packaging/versions.json') -Raw | ConvertFrom-Json
  $enginePin = (Get-ArchitecturePins $pins $Arch).singBox
  Assert-EnginePins $enginePin (Join-Path $app 'engine/SHA256SUMS.txt') $Arch
  foreach ($file in $enginePin.files.PSObject.Properties) {
    $installed = Join-Path $app "engine/$($file.Name)"
    Assert-Hash $installed $file.Value
    Assert-PeArchitecture $installed $Arch
  }
  foreach ($file in @('runtime/node.exe', 'helper/netswitch-helper.exe')) {
    Assert-PeArchitecture (Join-Path $app $file) $Arch
  }
  # The startup task runs the helper directly; a console program would open a window.
  Assert-PeWindowless (Join-Path $app 'helper/netswitch-helper.exe')
  Assert-PeArchitecture (Join-Path $app 'tray/NetSwitchTray.exe') 'AnyCPU'
  if (-not $enginePin.files.PSObject.Properties['libcronet.dll'] -and
      (Test-Path -LiteralPath (Join-Path $app 'engine/libcronet.dll'))) {
    throw 'Installed engine has an unpinned libcronet.dll.'
  }
  foreach ($license in $pins.licenses.cronetNative) {
    $file = Join-Path (Join-Path $app 'licenses') $license.installPath
    if ((Get-FileHash -LiteralPath $file -Algorithm SHA256).Hash -ne $license.sha256) {
      throw "Installed native license hash mismatch: $file"
    }
  }
  if ((Get-FileHash -LiteralPath (Join-Path $app 'licenses/wintun-LICENSE.txt')).Hash -ne $pins.licenses.wintun.sha256) {
    throw 'Installed Wintun license hash mismatch'
  }
  if ((Get-FileHash -LiteralPath (Join-Path $app 'licenses/go-LICENSE.txt')).Hash -ne $pins.licenses.go.sha256) {
    throw 'Installed Go license hash mismatch'
  }
  Write-Host 'Installed files and shortcut are in place'
}

function Get-AppProcesses {
  $engine = Join-Path $app 'engine\sing-box.exe'
  $helper = Join-Path $app 'helper\netswitch-helper.exe'
  $server = Join-Path $app 'server.mjs'
  $trayArgument = '-File "' + (Join-Path $app 'tray.ps1') + '"'
  Get-CimInstance Win32_Process -Filter "Name = 'node.exe' OR Name = 'sing-box.exe' OR Name = 'netswitch-helper.exe' OR Name = 'NetSwitchTray.exe' OR Name = 'powershell.exe'" |
    Where-Object {
      $_.ExecutablePath -eq $engine -or
      $_.ExecutablePath -eq $helper -or
      $_.ExecutablePath -eq $trayProgram -or
      ($_.ExecutablePath -eq $node -and $_.CommandLine -and $_.CommandLine.IndexOf($server, [StringComparison]::OrdinalIgnoreCase) -ge 0) -or
      ($_.Name -eq 'powershell.exe' -and $_.CommandLine -and $_.CommandLine.IndexOf($trayArgument, [StringComparison]::OrdinalIgnoreCase) -ge 0)
    }
}

function Remember-BrowserProcesses {
  # Follow only our launcher descendants, never all browser processes by name.
  # Keep creation times too, so a recycled PID cannot make cleanup kill another app.
  $processes = @(Get-CimInstance Win32_Process)
  foreach ($launcher in $launchers) { $launchDescendants[[int]$launcher.Id] = $launcher.StartTime }
  do {
    $added = $false
    foreach ($process in $processes) {
      $parentId = [int]$process.ParentProcessId
      $processId = [int]$process.ProcessId
      if ($launchDescendants.ContainsKey($parentId) -and
          $process.CreationDate -ge $launchDescendants[$parentId] -and
          -not $launchDescendants.ContainsKey($processId)) {
        $launchDescendants[$processId] = $process.CreationDate
        $added = $true
        if ($process.Name -in @('chrome.exe', 'msedge.exe', 'firefox.exe', 'iexplore.exe')) {
          $browserProcesses[$processId] = $process.CreationDate
        }
      }
    }
  } while ($added)
}

function Wait-HelperModes([string[]] $Modes) {
  try {
    Wait-Until {
      $helpers = @(Get-AppProcesses | Where-Object { $_.Name -eq 'netswitch-helper.exe' })
      foreach ($mode in $Modes) {
        # Match the first argument, not an arbitrary occurrence in a path or flag.
        $pattern = '^(?:"[^"]+"|\S+)\s+' + [regex]::Escape($mode) + '(?:\s|$)'
        if (@($helpers | Where-Object { $_.CommandLine -match $pattern }).Count -ne 1) { return $false }
      }
      return $true
    } ("Expected one installed helper for each mode: " + ($Modes -join ', '))
  } catch {
    Get-AppProcesses | Where-Object { $_.Name -eq 'netswitch-helper.exe' } |
      Select-Object ProcessId, CommandLine | Format-List | Out-Host
    throw
  }
}

function Wait-Until([scriptblock] $Condition, [string] $Failure, [int] $Seconds = 60) {
  $deadline = (Get-Date).AddSeconds($Seconds)
  do {
    Remember-BrowserProcesses
    if (& $Condition) { return }
    Start-Sleep -Milliseconds 500
  } while ((Get-Date) -lt $deadline)
  throw $Failure
}

function Start-InstalledApp {
  if (@(Get-AppProcesses).Count) { throw 'Installed app processes already exist before launch.' }
  # PrepareToInstall force-stops only the app's own processes. Its old server
  # record can remain; launch.ps1 must recognize that and replace it itself.
  $shell = New-Object -ComObject WScript.Shell
  $link = $null
  try {
    $link = $shell.CreateShortcut($shortcut)
    # Execute exactly the installed shortcut's target, arguments and working dir.
    # No RunAs here: launch.ps1 must perform its own server elevation.
    $process = Start-Process -FilePath $link.TargetPath -ArgumentList $link.Arguments -WorkingDirectory $link.WorkingDirectory -WindowStyle Hidden -PassThru
    $launchers.Add($process)
  } finally {
    if ($null -ne $link) { [void][Runtime.InteropServices.Marshal]::ReleaseComObject($link) }
    [void][Runtime.InteropServices.Marshal]::ReleaseComObject($shell)
  }
  $script:runningServer = $null
  Wait-Until {
    if (-not (Test-Path -LiteralPath $serverFile)) { return $false }
    try {
      $saved = Get-Content -LiteralPath $serverFile -Raw | ConvertFrom-Json
      $ping = Invoke-RestMethod -Uri "http://127.0.0.1:$($saved.port)/api/ping" -Headers @{ 'X-Token' = $saved.token } -TimeoutSec 2
      if ($ping.ok -ne $true) { return $false }
      $owner = @(Get-AppProcesses | Where-Object { $_.ProcessId -eq $saved.pid -and $_.ExecutablePath -eq $node })
      if ($owner.Count -ne 1) { throw 'server.json does not belong to the installed Node server.' }
      $script:runningServer = $saved
      return $true
    } catch { return $false }
  } 'Installed shortcut did not create an authenticated, reachable server within 60 seconds.'
  # An installed copy runs its tray icon as tray\NetSwitchTray.exe, never as
  # tray.ps1 in PowerShell. Stop-InstalledApp then checks it notices the quit and ends.
  Wait-Until { @(Get-AppProcesses | Where-Object { $_.ExecutablePath -eq $trayProgram }).Count -gt 0 } 'Installed shortcut did not start tray\NetSwitchTray.exe.'
  Wait-HelperModes @('meters', 'outside', 'network')
  # Routing starts automatically. Require the real engine before
  # exercising quit, upgrade and uninstall, so each shutdown path covers all modes.
  $script:routingState = $null
  try {
    Wait-Until {
      $state = Invoke-RestMethod -Uri "http://127.0.0.1:$($script:runningServer.port)/api/state" -Headers @{ 'X-Token' = $script:runningServer.token } -TimeoutSec 5
      $script:routingState = $state.routing
      return $state.routing.status -eq 'on'
    } 'Installed routing engine did not turn on.'
  } catch {
    Write-Host ($script:routingState | ConvertTo-Json -Compress)
    throw
  }
  # Assert-Installed checks the PE headers of Node, helper and engine (and the
  # tray's AnyCPU image). IsWow64Process2 cannot distinguish emulated x64 from
  # native ARM64, so do not claim it proves these processes run natively.
  Wait-Until { $process.HasExited } 'The installed launcher did not finish opening the app window.'
  $process.WaitForExit()
  if ($process.ExitCode -ne 0) { throw "Installed launcher exited with code $($process.ExitCode)." }
  if (-not (Test-Path -LiteralPath $machineData)) { throw 'Installed server did not create its ProgramData directory.' }
  if (@(Get-AppProcesses | Where-Object { $_.ExecutablePath -eq $trayProgram }).Count -ne 1) { throw 'The installed tray program did not keep running after the launcher finished.' }
  if (@(Get-AppProcesses | Where-Object { $_.Name -eq 'powershell.exe' }).Count) { throw 'The installed copy ran tray.ps1 instead of tray\NetSwitchTray.exe.' }
  Wait-Routing $script:runningServer
  Write-Host 'Installed shortcut started its own server and tray program; authenticated ping succeeded; routing is on'
  return $script:runningServer
}

# A server that answers is not enough: the routing engine must really be on.
function Wait-Routing($Server) {
  $script:lastRouting = $null
  try {
    Wait-Until {
      try {
        $state = Invoke-RestMethod -Uri "http://127.0.0.1:$($Server.port)/api/state" -Headers @{ 'X-Token' = $Server.token } -TimeoutSec 5
        $script:lastRouting = $state.routing
        return $state.routing.status -eq 'on'
      } catch { return $false }
    } 'Routing did not turn on.' 90
  } catch {
    throw "Routing did not turn on in the installed copy: $($script:lastRouting | ConvertTo-Json -Compress)"
  }
}

$schtasks = Join-Path $env:SystemRoot 'System32\schtasks.exe'
function Test-StartupTask([string] $Name) {
  $query = Start-Process -FilePath $schtasks -ArgumentList '/Query', '/TN', "`"\Net Switch\$Name`"" -WindowStyle Hidden -Wait -PassThru
  return $query.ExitCode -eq 0
}

# What the Server task runs, through the Task Scheduler's own interface.
function Get-ServerTaskAction {
  $service = New-Object -ComObject Schedule.Service
  $service.Connect()
  $action = $service.GetFolder('\Net Switch').GetTask('Server').Definition.Actions.Item(1)
  return [pscustomobject]@{ Path = $action.Path; Arguments = $action.Arguments }
}

# Visible windows titled with the installed node.exe path. A console program's
# window carries its path as the title, whoever draws it: conhost, or Windows
# Terminal on Windows 11. Asking node.exe for its own main window doesn't work:
# under Windows Terminal it has none, even while its console shows on screen.
Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;
public static class NetSwitchSmokeWindows {
  delegate bool EnumProc(IntPtr window, IntPtr data);
  [DllImport("user32.dll")] static extern bool EnumWindows(EnumProc callback, IntPtr data);
  [DllImport("user32.dll")] static extern bool IsWindowVisible(IntPtr window);
  [DllImport("user32.dll", CharSet = CharSet.Unicode)] static extern int GetWindowText(IntPtr window, StringBuilder text, int size);
  public static List<string> Titles() {
    var titles = new List<string>();
    EnumWindows((window, data) => {
      if (!IsWindowVisible(window)) return true;
      var text = new StringBuilder(512);
      GetWindowText(window, text, 512);
      if (text.Length > 0) titles.Add(text.ToString());
      return true;
    }, IntPtr.Zero);
    return titles;
  }
}
'@
function Get-NodeWindows {
  @([NetSwitchSmokeWindows]::Titles() | Where-Object { $_.IndexOf($node, [StringComparison]::OrdinalIgnoreCase) -ge 0 })
}

# Waits for the server a task started, and returns its server.json.
function Wait-TaskServer([string] $Failure) {
  $script:runningServer = $null
  Wait-Until {
    try {
      $saved = Get-Content -LiteralPath $serverFile -Raw | ConvertFrom-Json
      $ping = Invoke-RestMethod -Uri "http://127.0.0.1:$($saved.port)/api/ping" -Headers @{ 'X-Token' = $saved.token } -TimeoutSec 2
      if ($ping.ok -eq $true) { $script:runningServer = $saved; return $true }
    } catch {}
    return $false
  } $Failure 120
  return $script:runningServer
}

function Set-ServerTaskAction([string] $Path, [string] $Arguments) {
  $service = New-Object -ComObject Schedule.Service
  $service.Connect()
  $folder = $service.GetFolder('\Net Switch')
  $definition = $folder.GetTask('Server').Definition
  $action = $definition.Actions.Item(1)
  $action.Path = $Path
  $action.Arguments = $Arguments
  [void]$folder.RegisterTaskDefinition('Server', $definition, 4, $null, $null, $definition.Principal.LogonType)
}

function Stop-InstalledApp($Server) {
  $null = Invoke-RestMethod -Method Post -Uri "http://127.0.0.1:$($Server.port)/api/quit" -Headers @{ 'X-Token' = $Server.token } -ContentType 'application/json' -Body '{}' -TimeoutSec 60
  Wait-Until { -not (Test-Path -LiteralPath $serverFile) } '/api/quit did not remove server.json.'
  Wait-Until { @(Get-AppProcesses).Count -eq 0 } 'Installed app or tray remained after /api/quit.'
}

$node = Join-Path $app 'runtime\node.exe'
$trayProgram = Join-Path $app 'tray\NetSwitchTray.exe'

try {
Invoke-Setup 'install'
Assert-Installed

$version = & $node --version
Write-Host "Bundled Node.js $version"
$nodeArch = & $node -p process.arch
if ($LASTEXITCODE -ne 0 -or $nodeArch -ne $Arch) { throw "Bundled Node runs as $nodeArch, expected $Arch" }

# The installed engine files must pass the same checksum check Net Switch runs before every start.
$engineModule = ([Uri](Join-Path $app 'lib\engine.mjs')).AbsoluteUri
$check = "const { Engine } = await import(process.argv[1]); const engine = new Engine({ singBoxPath: process.argv[2], dataDir: process.env.TEMP, mode: 'proxy' }); await engine.verifyEngineFiles(); console.log('Engine files match their checksums');"
& $node --input-type=module -e $check $engineModule (Join-Path $app 'engine\sing-box.exe')
if ($LASTEXITCODE -ne 0) { throw 'The installed engine files failed their checksum check' }

# With nothing recorded, the restore tool must say so and succeed.
$emptyRecord = Join-Path $logs 'empty-undo-record'
New-Item -ItemType Directory -Force -Path $emptyRecord | Out-Null
& $node (Join-Path $app 'tools\restore-windows.mjs') --machine-data $emptyRecord
if ($LASTEXITCODE -ne 0) { throw 'restore-windows.mjs failed with nothing to undo' }

$server = Start-InstalledApp
Stop-InstalledApp $server

# Leave routing and all four helper modes running for PrepareToInstall to stop.
$server = Start-InstalledApp
Invoke-Setup 'reinstall'
Assert-Installed
Wait-Until { @(Get-AppProcesses).Count -eq 0 } 'Reinstall failed to stop the installed processes.'
# A successful restart also proves the reinstalled payload is usable.
$server = Start-InstalledApp

# Starting with Windows: two scheduled tasks. Then what sign-in runs must start
# the server through the task, which asks for no permission.
$state = Invoke-RestMethod -Method Post -Uri "http://127.0.0.1:$($server.port)/api/settings" -Headers @{ 'X-Token' = $server.token } -ContentType 'application/json' -Body '{"autostart":true}' -TimeoutSec 60
if ($state.settings.autostart -ne $true) { throw 'Turning on starting with Windows did not stick.' }
foreach ($name in 'Server', 'Sign-in') {
  if (-not (Test-StartupTask $name)) { throw "Startup task missing: $name" }
}
# The Server task starts node.exe through the windowless helper: run directly
# by the task, the console program node.exe opens a window on the desktop.
$helperProgram = Join-Path $app 'helper\netswitch-helper.exe'
$serverAction = Get-ServerTaskAction
$expectedArguments = "run `"$node`" `"$(Join-Path $app 'server.mjs')`" --user-data `"$userData`" --machine-data `"$machineData`""
if ($serverAction.Path -ne $helperProgram -or $serverAction.Arguments -ne $expectedArguments) {
  throw "The Server task runs $($serverAction.Path) $($serverAction.Arguments)"
}
Stop-InstalledApp $server

# A 0.3.0 task ran node.exe directly, which showed a console window. Start the
# server that way once, so the window check below is known to see such a
# window on this machine; otherwise "no window" would prove nothing.
$legacyArguments = "`"$(Join-Path $app 'server.mjs')`" --user-data `"$userData`" --machine-data `"$machineData`""
Set-ServerTaskAction $node $legacyArguments
$taskStart = Start-Process -FilePath $schtasks -ArgumentList '/Run', '/TN', '"\Net Switch\Server"' -WindowStyle Hidden -Wait -PassThru
if ($taskStart.ExitCode -ne 0) { throw "Running the 0.3.0-style Server task failed (schtasks exit code $($taskStart.ExitCode))." }
$server = Wait-TaskServer 'The 0.3.0-style Server task did not bring up the server within 120 seconds.'
Wait-Until { @(Get-NodeWindows).Count -gt 0 } 'The window check saw no window for the 0.3.0-style start, so it cannot be trusted here.' 30
Write-Host 'The window check sees the console window of the 0.3.0-style start'
# The server started that way repairs its own task in the background, for a
# task the installer missed.
Wait-Until {
  $action = Get-ServerTaskAction
  return $action.Path -eq $helperProgram -and $action.Arguments -eq $expectedArguments
} 'The server did not update the 0.3.0-style task it was started by.' 60
Write-Host 'A server started by a 0.3.0-style task updates the task itself'
Stop-InstalledApp $server

# The installer's update step must point a 0.3.0 task at the helper, keeping
# its arguments, and leave a current one alone.
Set-ServerTaskAction $node $legacyArguments
$update = & $node (Join-Path $app 'tools\update-autostart.mjs')
if ($LASTEXITCODE -ne 0 -or "$update" -notmatch 'Startup task: updated') { throw "Updating a 0.3.0 startup task failed: $update" }
$serverAction = Get-ServerTaskAction
if ($serverAction.Path -ne $helperProgram -or $serverAction.Arguments -ne $expectedArguments) {
  throw "The updated Server task runs $($serverAction.Path) $($serverAction.Arguments)"
}
$update = & $node (Join-Path $app 'tools\update-autostart.mjs')
if ($LASTEXITCODE -ne 0 -or "$update" -notmatch 'Startup task: current') { throw "A current startup task was not left alone: $update" }
Write-Host 'A 0.3.0 startup task is updated to start the server without a window'
$signIn = Start-Process -FilePath $windowsPowerShell -ArgumentList '-NoProfile', '-ExecutionPolicy', 'Bypass', '-WindowStyle', 'Hidden', '-File', "`"$(Join-Path $app 'launch.ps1')`"", '-Background' -WindowStyle Hidden -PassThru
$launchers.Add($signIn)
$server = Wait-TaskServer 'The sign-in start did not bring up the server within 120 seconds.'
$serverProcess = Get-CimInstance Win32_Process -Filter "ProcessId = $($server.pid)"
$parent = Get-CimInstance Win32_Process -Filter "ProcessId = $($serverProcess.ParentProcessId)"
$grandparent = if ($parent) { Get-CimInstance Win32_Process -Filter "ProcessId = $($parent.ParentProcessId)" } else { $null }
$chain = '{0} <- {1}' -f $(if ($parent) { $parent.Name } else { 'gone' }), $(if ($grandparent) { $grandparent.Name } else { 'gone' })
# The Task Scheduler service starts the windowless helper, which starts the
# server. A permission prompt would make the launcher its parent.
if (-not $parent -or $parent.ExecutablePath -ne $helperProgram -or $parent.CommandLine -notmatch ' run ' -or
    -not $grandparent -or $grandparent.Name -ne 'svchost.exe') {
  throw "The sign-in start did not use the startup task through the helper (the server's parents: $chain)."
}
# No window on screen for the server (checked a few seconds in, when the
# 0.3.0-style start above already showed one).
Start-Sleep -Seconds 3
$windows = @(Get-NodeWindows)
if ($windows.Count) { throw "The server started at sign-in shows a window: $($windows -join ', ')" }
Write-Host 'The server started at sign-in shows no window'
Wait-Until { $signIn.HasExited } 'The sign-in start did not finish.' 120
if ($signIn.ExitCode -ne 0) { throw "The sign-in start exited with code $($signIn.ExitCode)." }
Wait-Until { @(Get-AppProcesses | Where-Object { $_.ExecutablePath -eq $trayProgram }).Count -eq 1 } 'The sign-in start did not start the tray program.'
Wait-Routing $server
Write-Host 'Starting with Windows works: the sign-in start ran the server through its task, with routing on'

# Left running, and starting with Windows left on, to exercise
# InitializeUninstall's stop path and the removal of the startup tasks.
$userMarker = Join-Path $userData 'installer-smoke-retain.txt'
[IO.File]::WriteAllText($userMarker, 'User data must survive uninstall.')

# Exercise cleanup on real installer leftovers, including links outside them.
# All fixtures belong to this disposable runner; establish their ACLs before
# planting links so fixture setup itself never rewrites a linked target.
# RUNNER_TEMP can be on D: while ProgramData is on C:. A hard link must
# reference the same volume; this sibling is outside every cleanup pattern.
$cleanupOutside = Join-Path $env:ProgramData ('netswitch-cleanup-outside-' + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $cleanupOutside | Out-Null
$cleanupRecord = Join-Path $cleanupOutside 'record'
[IO.File]::WriteAllText($cleanupRecord, 'outside uninstall cleanup')
$cleanupOutsideACL = (Get-Acl -LiteralPath $cleanupOutside).Sddl
$cleanupRecordACL = (Get-Acl -LiteralPath $cleanupRecord).Sddl
$cleanupArtifacts = @("$machineData.untrusted-$('1' * 24)", "$machineData.migrating")
foreach ($fixture in $cleanupArtifacts) {
  New-Item -ItemType Directory -Path $fixture | Out-Null
  $security = New-Object Security.AccessControl.DirectorySecurity
  $security.SetSecurityDescriptorSddlForm('O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)')
  Set-Acl -LiteralPath $fixture -AclObject $security
  New-Item -ItemType Junction -Path (Join-Path $fixture 'junction') -Target $cleanupOutside | Out-Null
  New-Item -ItemType HardLink -Path (Join-Path $fixture 'hardlink') -Target $cleanupRecord | Out-Null
  if (-not (Test-Path -LiteralPath (Join-Path $fixture 'hardlink'))) { throw 'Cleanup fixture was not created.' }
}
$cleanupUntrusted = "$machineData.untrusted-$('2' * 24)"
New-Item -ItemType Directory -Path $cleanupUntrusted | Out-Null
$security = Get-Acl -LiteralPath $cleanupUntrusted
$security.SetOwner([Security.Principal.WindowsIdentity]::GetCurrent().User)
Set-Acl -LiteralPath $cleanupUntrusted -AclObject $security

# Inno keeps the original process alive while its TEMP copy runs. -Wait waits
# for that handoff; then check the final filesystem state (including self-delete).
$uninstallLog = Join-Path $logs 'uninstall.log'
$uninstall = Start-Process -FilePath (Join-Path $app 'unins000.exe') -ArgumentList '/VERYSILENT', '/SUPPRESSMSGBOXES', '/NORESTART', "/LOG=`"$uninstallLog`"" -WindowStyle Hidden -Wait -PassThru
if ($uninstall.ExitCode -ne 0) { throw "Uninstall exited with code $($uninstall.ExitCode)" }
Wait-Until { -not (Test-Path -LiteralPath $app) } 'Uninstall left the program folder behind.' 90
foreach ($link in @($shortcut, $desktopShortcut)) {
  if (Test-Path -LiteralPath $link) { throw "Uninstall left a shortcut behind: $link" }
}
if (@(Get-AppProcesses).Count) { throw 'Uninstall left an app process behind.' }
foreach ($name in 'Server', 'Sign-in') {
  if (Test-StartupTask $name) { throw "Uninstall left a startup task behind: $name" }
}
if (-not (Test-Path -LiteralPath $userMarker)) { throw 'Uninstall deleted user data.' }
$uninstallText = Get-Content -LiteralPath $uninstallLog -Raw
if ($uninstallText -match 'Net Switch Windows restore result: 0') {
  if (Test-Path -LiteralPath $machineData) { throw 'Successful restore left ProgramData behind.' }
  if ($uninstallText -notmatch 'Net Switch machine cleanup result: 0') { throw 'Machine cleanup did not succeed.' }
  foreach ($fixture in $cleanupArtifacts) {
    if (Test-Path -LiteralPath $fixture) { throw "Uninstall left admin-owned recovery data: $fixture" }
  }
  $remaining = @(Get-ChildItem -LiteralPath $env:ProgramData -Filter 'Net Switch.migrating*')
  if ($remaining.Count) { throw 'Uninstall left quarantined staging data.' }
  if (Test-Path 'HKLM:\SOFTWARE\NetSwitch.ControlDirectoryCertificates.v1') { throw 'Uninstall left its certification key.' }
} elseif ($uninstallText -match 'Net Switch Windows restore result: -?\d+') {
  # A runner may lack an adapter needed to undo routing. The record must survive.
  $undo = Join-Path $machineData 'windows-undo.json'
  if (-not (Test-Path -LiteralPath $undo) -or (Get-Item -LiteralPath $undo).Length -eq 0) {
    throw 'Restore failed but the Windows undo record was not preserved.'
  }
  Write-Host 'Windows restore could not finish; uninstall preserved its undo record'
} else { throw 'Uninstall log does not show whether Windows settings were restored.' }
if (-not (Test-Path -LiteralPath $cleanupUntrusted)) { throw 'Uninstall removed non-admin-owned data.' }
if ((Get-Acl -LiteralPath $cleanupOutside).Sddl -ne $cleanupOutsideACL -or
    (Get-Acl -LiteralPath $cleanupRecord).Sddl -ne $cleanupRecordACL -or
    [IO.File]::ReadAllText($cleanupRecord) -ne 'outside uninstall cleanup') {
  throw 'Uninstall followed a link or changed its outside target.'
}
Write-Host 'Uninstall cleanup kept link targets and non-admin-owned data unchanged'
Write-Host 'Uninstall removed the program and its shortcut'
Write-Host 'Installer smoke test passed'
} catch {
  # Logs explain whether a failure was launch, shutdown, installer or restoration.
  # Redact the launch URL token before putting diagnostics in public CI output.
  foreach ($log in @((Join-Path $userData 'launch.log'), (Join-Path $userData 'server.log'), (Join-Path $userData 'tray.log')) + @(Get-ChildItem -LiteralPath $logs -Filter '*.log' | ForEach-Object FullName)) {
    if (Test-Path -LiteralPath $log) {
      Write-Host "Diagnostic log: $log"
      Get-Content -LiteralPath $log -Tail 60 | ForEach-Object { $_ -replace '(?i)(token[=:]\s*)[a-z0-9]+', '$1[redacted]' } | Write-Host
    }
  }
  throw
} finally {
  Remember-BrowserProcesses
  foreach ($processId in @($browserProcesses.Keys)) {
    $current = Get-CimInstance Win32_Process -Filter "ProcessId = $processId"
    if ($current -and $current.CreationDate -eq $browserProcesses[$processId]) {
      Stop-Process -Id $processId -Force -ErrorAction SilentlyContinue
    }
  }
  foreach ($launcher in $launchers) {
    if (-not $launcher.HasExited) { $launcher.Kill() }
    $launcher.Dispose()
  }
  if (Test-Path -LiteralPath (Join-Path $app 'tools\stop.ps1')) {
    & $windowsPowerShell -NoProfile -ExecutionPolicy Bypass -File (Join-Path $app 'tools\stop.ps1') -AppDir $app
    if ($LASTEXITCODE -ne 0) { Write-Warning 'Failure cleanup could not stop the installed app; see its logs.' }
  }
}
