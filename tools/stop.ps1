# Stops a running Net Switch: its server, its routing engine and its tray icon.
# The installer runs this (as administrator) before upgrading or uninstalling.
#
#   powershell -NoProfile -ExecutionPolicy Bypass -File tools\stop.ps1 -AppDir "C:\Program Files\Net Switch"
#
# Only these processes of this copy are stopped, matched exactly:
# - its routing engine: <AppDir>\engine\sing-box.exe;
# - its server: <AppDir>\runtime\node.exe running <AppDir>\server.mjs;
# - its tray icon: powershell.exe running -File "<AppDir>\tray.ps1".
# Nothing else is touched: not the installer or uninstaller, not other copies,
# not other programs called node.exe or powershell.exe, and not an editor that
# happens to have tray.ps1 open. Stopping the engine puts Windows routing back
# to normal.
# Exit code 0: none of these is left running. 1: something is.
param(
  [Parameter(Mandatory = $true)] [string] $AppDir
)

$ErrorActionPreference = 'Stop'
$app = [System.IO.Path]::GetFullPath($AppDir).TrimEnd('\')
$engine = "$app\engine\sing-box.exe"
$node = "$app\runtime\node.exe"
$server = "$app\server.mjs"
$trayArgument = "-File `"$app\tray.ps1`""

function Test-Same([string] $a, [string] $b) {
  return [string]::Equals($a, $b, [System.StringComparison]::OrdinalIgnoreCase)
}

function Test-Contains([string] $text, [string] $part) {
  return $text -and $text.IndexOf($part, [System.StringComparison]::OrdinalIgnoreCase) -ge 0
}

function Get-OwnProcesses {
  @(Get-CimInstance Win32_Process | Where-Object {
      (Test-Same $_.ExecutablePath $engine) -or
      ((Test-Same $_.ExecutablePath $node) -and (Test-Contains $_.CommandLine $server)) -or
      ($_.Name -ieq 'powershell.exe' -and (Test-Contains $_.CommandLine $trayArgument))
    })
}

$deadline = (Get-Date).AddSeconds(20)
do {
  $running = Get-OwnProcesses
  if ($running.Count -eq 0) { exit 0 }
  foreach ($process in $running) {
    Stop-Process -Id $process.ProcessId -Force -ErrorAction SilentlyContinue
  }
  Start-Sleep -Milliseconds 500
} while ((Get-Date) -lt $deadline)

$left = Get-OwnProcesses
if ($left.Count -eq 0) { exit 0 }
Write-Output ("Still running: " + (($left | ForEach-Object { "$($_.Name) ($($_.ProcessId))" }) -join ', '))
exit 1
