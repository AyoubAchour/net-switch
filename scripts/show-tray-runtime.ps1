# CI diagnostic: inspect the CLR actually loaded by an existing test tray.
# The compiler architecture and the tray's AnyCPU header cannot tell us this.
[CmdletBinding()]
param([Parameter(Mandatory = $true)][int] $ProcessId)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot 'build-common.ps1')

$trayProcess = Get-Process -Id $ProcessId
try {
  $modules = @($trayProcess.Modules | Where-Object { $_.ModuleName -ieq 'clr.dll' })
  if ($modules.Count -ne 1) { throw "Expected one loaded CLR in tray process $ProcessId, found $($modules.Count)." }
  $runtimePath = $modules[0].FileName
  $arch = if ($runtimePath -match '\\FrameworkArm64\\') { 'arm64' }
          elseif ($runtimePath -match '\\Framework64\\') { 'x64' }
          elseif ($runtimePath -match '\\Framework\\') { 'x86' }
          else { throw "Unrecognized tray CLR: $runtimePath" }
  # Verify the loaded DLL's machine type too, not just its directory name.
  Assert-PeArchitecture $runtimePath $arch
  Write-Output "Tray loaded runtime: $arch; PID=$ProcessId; $runtimePath"
} finally {
  $trayProcess.Dispose()
}
