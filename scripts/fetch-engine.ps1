# Windows PowerShell 5.1. Puts this PC's pinned routing engine into engine\,
# checked against packaging\versions.json and that architecture's checksum
# list, so a source checkout can turn routing on. Never starts it. The download
# is cached like the release build's: in dist\cache, or in the folder
# NETSWITCH_CACHE names (to share one cache between git worktrees).
#
#   powershell -NoProfile -ExecutionPolicy Bypass -File scripts\fetch-engine.ps1
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
Set-StrictMode -Version Latest
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
Add-Type -AssemblyName System.IO.Compression.FileSystem
. (Join-Path $PSScriptRoot 'build-common.ps1')

$repoRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$arch = Get-NativeArchitecture
$pins = Get-Content -LiteralPath (Join-Path $repoRoot 'packaging/versions.json') -Raw | ConvertFrom-Json
$pin = (Get-ArchitecturePins $pins $arch).singBox
Assert-EnginePins $pin (Get-EngineChecksumFile $repoRoot $arch) $arch
$cache = Get-BuildCache (Join-Path $repoRoot 'dist')
if (Test-Path -LiteralPath $cache) { Assert-NoLink $cache }
else { New-Item -ItemType Directory -Path $cache -Force | Out-Null }
$zip = Get-Artifact $pin $cache
$engine = Join-Path $repoRoot 'engine'
Assert-NoLink $engine
foreach ($file in $pin.files.PSObject.Properties) {
  $destination = Join-Path $engine $file.Name
  if (Test-Path -LiteralPath $destination) {
    Assert-NoLink $destination
    # Already there and right: nothing to do. Anything else is replaced.
    if ((Get-FileHash -LiteralPath $destination -Algorithm SHA256).Hash.ToLowerInvariant() -eq $file.Value) { continue }
    Remove-Item -LiteralPath $destination -Force
  }
  Copy-ArchiveFile $zip "$($pin.archiveRoot)/$($file.Name)" $destination
  Assert-Hash $destination $file.Value
  Assert-PeArchitecture $destination $arch
}
Write-Host "The $arch routing engine is in $engine"
