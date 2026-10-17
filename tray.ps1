# Net Switch's tray icon: both lines' load at a glance, their speeds on hover,
# a quick flyout on click, and a menu to open or quit Net Switch. launch.ps1 starts it as the normal user,
# never as administrator, so opening the window works the way the shortcut does.
# One copy runs per data folder; another copy exits at once.
# launch.ps1 starts the tray as its own program, NetSwitchTray.exe, when that is
# built (lib\tray-main.cs does what this script does, without PowerShell); this
# script is the fallback, and compiles lib\tray.cs at each start. Keep the two in step.
param(
  # The folder holding server.json, where tray.log is written: what launch.ps1
  # passes. A relative path is taken from this folder, so `-DataDir data-test`
  # watches test mode (node server.mjs --dev-proxy).
  [string] $DataDir = 'data'
)

$ErrorActionPreference = 'Stop'
$root = $PSScriptRoot
$dataPath = if ([System.IO.Path]::IsPathRooted($DataDir)) { $DataDir } else { Join-Path $root $DataDir }
$dataPath = [System.IO.Path]::GetFullPath($dataPath)
$logFile = Join-Path $dataPath 'tray.log'

# A mutex name can't hold backslashes, so the folder is named by its hash.
$sha = [System.Security.Cryptography.SHA256]::Create()
$hash = -join ($sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($dataPath.ToLowerInvariant()))[0..7] | ForEach-Object { $_.ToString('x2') })
$mutex = New-Object System.Threading.Mutex($false, "Local\NetSwitchTray-$hash")
try {
  if (-not $mutex.WaitOne(0)) { exit 0 }
} catch [System.Threading.AbandonedMutexException] {
  # The previous copy ended without letting go; this one takes over.
}

try {
  Add-Type -Path (Join-Path $root 'lib\tray.cs') -ReferencedAssemblies System.Windows.Forms, System.Drawing, System.Net.Http, System.Web.Extensions
} catch {
  $line = "$((Get-Date).ToUniversalTime().ToString('o')) the tray icon could not start: $($_.Exception.Message)"
  Add-Content -LiteralPath $logFile -Value $line -ErrorAction SilentlyContinue
  exit 1
}

# The icon may start Net Switch through launch.ps1 only when it watches the
# folder launch.ps1 itself uses; a test-mode icon must never start real routing.
$launcherDir = if (Test-Path -LiteralPath (Join-Path $root 'runtime\node.exe')) { Join-Path $env:LOCALAPPDATA 'Net Switch' } else { Join-Path $root 'data' }
$canLaunch = [System.IO.Path]::GetFullPath($launcherDir).TrimEnd('\') -ieq $dataPath.TrimEnd('\')
[NetSwitch.Tray]::Run($root, $dataPath, $logFile, $canLaunch)
$mutex.ReleaseMutex()
