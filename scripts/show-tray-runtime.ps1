# CI diagnostic, run after the tray tests: inspect the CLR actually loaded.
# The compiler architecture and the tray's AnyCPU header cannot tell us this.
# This separate step keeps PowerShell startup outside the timed tray cases.
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot 'build-common.ps1')

$trayPath = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\tray\bin\NetSwitchTray.exe'))
$dataDir = Join-Path ([IO.Path]::GetTempPath()) ('netswitch-tray-runtime-' + [Guid]::NewGuid().ToString('N'))
$trayProcess = $null
New-Item -ItemType Directory -Path $dataDir | Out-Null
try {
  # Like the single-instance test: a stale server file keeps the tray alive.
  # This temporary folder cannot launch Net Switch, and PID 0 is not a server.
  [IO.File]::WriteAllText((Join-Path $dataDir 'server.json'), '{"port":1,"token":"runtime-probe","pid":0}')
  $trayProcess = Start-Process -FilePath $trayPath -ArgumentList @('-DataDir', ('"' + $dataDir + '"')) -WindowStyle Hidden -PassThru
  $null = $trayProcess.Handle
  $watch = [Diagnostics.Stopwatch]::StartNew()
  $logPath = Join-Path $dataDir 'tray.log'
  do {
    $trayProcess.Refresh()
    if ($trayProcess.HasExited) { throw "The runtime probe tray exited early: $($trayProcess.ExitCode)." }
    # Wait for managed code before enumerating modules during process startup.
    if ([IO.File]::Exists($logPath) -and [IO.File]::ReadAllText($logPath) -match ' started\r?\n') { break }
    if ($watch.Elapsed.TotalSeconds -ge 60) { throw 'The runtime probe tray did not start within 60 seconds.' }
    Start-Sleep -Milliseconds 100
  } while ($true)
  $modules = @($trayProcess.Modules | Where-Object { $_.ModuleName -ieq 'clr.dll' })
  if ($modules.Count -ne 1) { throw "Expected one loaded CLR, found $($modules.Count)." }
  $runtimePath = $modules[0].FileName
  $arch = if ($runtimePath -match '\\FrameworkArm64\\') { 'arm64' }
          elseif ($runtimePath -match '\\Framework64\\') { 'x64' }
          elseif ($runtimePath -match '\\Framework\\') { 'x86' }
          else { throw "Unrecognized tray CLR: $runtimePath" }
  # Verify the loaded DLL's machine type too, not just its directory name.
  Assert-PeArchitecture $runtimePath $arch
  Write-Output "Tray loaded runtime: $arch; PID=$($trayProcess.Id); $runtimePath"
} finally {
  if ($null -ne $trayProcess) {
    try {
      if (-not $trayProcess.HasExited) { $trayProcess.Kill() }
      if (-not $trayProcess.WaitForExit(5000)) { throw "Runtime probe tray $($trayProcess.Id) survived cleanup." }
    } finally { $trayProcess.Dispose() }
  }
  # Only remove the fresh temporary directory this probe created, after exit.
  Remove-Item -LiteralPath $dataDir -Recurse -Force
}
