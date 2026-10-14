# Opens Net Switch. Starts its background server first if it isn't running
# (Windows asks for administrator permission), then the tray icon and the window.
# This script itself runs as the normal user; only the server is elevated.

$ErrorActionPreference = 'Stop'
$root = $PSScriptRoot

# An installed copy carries its own Node.js in runtime\ and keeps its data
# outside the program folder: the person's settings and logs in
# %LOCALAPPDATA%, the Windows undo record and engine files in %ProgramData%.
# A source checkout keeps everything in data\.
$bundledNode = Join-Path $root 'runtime\node.exe'
$installed = Test-Path -LiteralPath $bundledNode
if ($installed) {
  $userDir = Join-Path $env:LOCALAPPDATA 'Net Switch'
  $machineDir = Join-Path $env:ProgramData 'Net Switch'
} else {
  $userDir = Join-Path $root 'data'
  $machineDir = $userDir
}
# Created here, as the person, so the folder is theirs even though the
# elevated server writes into it.
New-Item -ItemType Directory -Force -Path $userDir | Out-Null
$serverFile = Join-Path $userDir 'server.json'
$launchLog = Join-Path $userDir 'launch.log'

function Write-LaunchLog([string] $text) {
  # Kept small: past 1 MB, the old log becomes launch.log.1.
  $old = Get-Item -LiteralPath $launchLog -ErrorAction SilentlyContinue
  if ($old -and $old.Length -gt 1MB) { Move-Item -LiteralPath $launchLog -Destination "$launchLog.1" -Force -ErrorAction SilentlyContinue }
  $line = "$((Get-Date).ToUniversalTime().ToString('o')) $text"
  Add-Content -LiteralPath $launchLog -Value $line -ErrorAction SilentlyContinue
}

function Show-Message([string] $text) {
  Add-Type -AssemblyName PresentationFramework
  [System.Windows.MessageBox]::Show($text, 'Net Switch') | Out-Null
}

function Get-RunningServer {
  if (-not (Test-Path -LiteralPath $serverFile)) { return $null }
  try {
    $saved = Get-Content -LiteralPath $serverFile -Raw | ConvertFrom-Json
    $null = Invoke-RestMethod -Uri "http://127.0.0.1:$($saved.port)/api/ping" -Headers @{ 'X-Token' = $saved.token } -TimeoutSec 2
    return $saved
  } catch {
    return $null
  }
}

# An installed copy always uses its own Node. A source checkout looks in fixed
# places, because a desktop shortcut doesn't load the shell profile: the fnm
# default version first, then a regular install, then whatever PATH has.
function Find-Node {
  if ($installed) { return $bundledNode }
  $fnmDir = if ($env:FNM_DIR) { $env:FNM_DIR } else { Join-Path $env:APPDATA 'fnm' }
  $candidates = @(
    (Join-Path $fnmDir 'aliases\default\node.exe'),
    (Join-Path $env:ProgramFiles 'nodejs\node.exe')
  )
  foreach ($candidate in $candidates) {
    if (Test-Path -LiteralPath $candidate) { return $candidate }
  }
  $onPath = Get-Command node -ErrorAction SilentlyContinue
  if ($onPath) { return $onPath.Source }
  return $null
}

function Find-Browser {
  foreach ($name in 'chrome.exe', 'msedge.exe') {
    foreach ($hive in 'HKCU:', 'HKLM:') {
      $path = (Get-ItemProperty "$hive\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\$name" -ErrorAction SilentlyContinue).'(default)'
      if ($path -and (Test-Path -LiteralPath $path)) { return $path }
    }
  }
  return $null
}

# The Windows error code inside an exception, if there is one.
function Get-NativeError($exception) {
  while ($exception) {
    if ($exception -is [System.ComponentModel.Win32Exception]) { return $exception.NativeErrorCode }
    $exception = $exception.InnerException
  }
  return $null
}

$server = Get-RunningServer
if (-not $server) {
  if (-not (Test-Path -LiteralPath (Join-Path $root 'server.mjs'))) {
    Show-Message "Net Switch's files are incomplete (server.mjs is missing from $root). Reinstall Net Switch."
    exit 1
  }
  $node = Find-Node
  if (-not $node) {
    Show-Message 'Net Switch needs Node.js 22 or newer, and it wasn''t found on this PC. The installer from the Releases page includes it.'
    exit 1
  }
  # An older Node fails part way into starting, with nothing in the log to say why.
  $version = (& $node --version 2>$null) -replace '^v', ''
  if (-not ($version -as [version]) -or [version]$version -lt [version]'22.0') {
    Show-Message "Net Switch needs Node.js 22 or newer, and this PC has $(if ($version) { $version } else { 'an unknown version' }) at $node."
    exit 1
  }
  # Paths are quoted by hand: Start-Process joins the list with plain spaces.
  $arguments = @(
    "`"$(Join-Path $root 'server.mjs')`"",
    '--user-data', "`"$userDir`"",
    '--machine-data', "`"$machineDir`""
  )
  try {
    Start-Process -FilePath $node -ArgumentList $arguments -WorkingDirectory $root -Verb RunAs -WindowStyle Hidden
  } catch {
    # 1223: the administrator prompt was declined. Nothing to open, nothing to report.
    if ((Get-NativeError $_.Exception) -eq 1223) { exit 0 }
    Write-LaunchLog "the server could not be started: $($_.Exception.Message)"
    Show-Message "Net Switch couldn't start its background service: $($_.Exception.Message)"
    exit 1
  }
  $deadline = (Get-Date).AddSeconds(30)
  while (-not ($server = Get-RunningServer)) {
    if ((Get-Date) -gt $deadline) {
      Write-LaunchLog 'the server did not answer within 30 seconds'
      Show-Message "Net Switch didn't start. The details are in server.log in $userDir"
      exit 1
    }
    Start-Sleep -Milliseconds 300
  }
}

# The tray icon runs as the normal user and stays after the window closes.
# When one is already running, this new copy exits at once.
try {
  $trayArguments = @(
    '-NoProfile', '-ExecutionPolicy', 'Bypass', '-WindowStyle', 'Hidden',
    '-File', "`"$(Join-Path $root 'tray.ps1')`"", '-DataDir', "`"$userDir`""
  )
  Start-Process -FilePath (Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe') -ArgumentList $trayArguments -WorkingDirectory $root -WindowStyle Hidden
} catch {
  # Net Switch works without its tray icon: say why in the log, and open the window anyway.
  Write-LaunchLog "the tray icon could not be started: $($_.Exception.Message)"
}

$url = "http://127.0.0.1:$($server.port)/#token=$($server.token)"
$browser = Find-Browser
if ($browser) {
  Start-Process -FilePath $browser -ArgumentList "--app=$url", '--window-size=800,700'
} else {
  Start-Process $url
}
