# Windows PowerShell 5.1. Puts the pinned routing engine (sing-box.exe and
# libcronet.dll) into engine\, checked against packaging\versions.json and
# engine\SHA256SUMS.txt, so a source checkout can turn routing on. The download
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
$cache = if ($env:NETSWITCH_CACHE) { [IO.Path]::GetFullPath($env:NETSWITCH_CACHE) } else { Join-Path $repoRoot 'dist\cache' }
$engine = Join-Path $repoRoot 'engine'
$pins = Get-Content -LiteralPath (Join-Path $repoRoot 'packaging/versions.json') -Raw | ConvertFrom-Json

# The app checks the engine against this list before every start, so the pins
# must agree with it.
$sums = @{}
foreach ($line in Get-Content -LiteralPath (Join-Path $engine 'SHA256SUMS.txt')) {
  if ($line -match '^([a-fA-F0-9]{64})\s+\*?([^\s]+)\s*$') { $sums[$Matches[2]] = $Matches[1].ToLowerInvariant() }
}
foreach ($file in $pins.singBox.files.PSObject.Properties) {
  if ($sums[$file.Name] -ne $file.Value) { throw "Engine pin disagrees with engine\SHA256SUMS.txt: $($file.Name)" }
}

foreach ($directory in @($cache, $engine)) {
  if (Test-Path -LiteralPath $directory) { Assert-NoLink $directory }
  else { New-Item -ItemType Directory -Path $directory -Force | Out-Null }
}
$archive = Get-Artifact $pins.singBox $cache
foreach ($file in $pins.singBox.files.PSObject.Properties) {
  $destination = Join-Path $engine $file.Name
  if (Test-Path -LiteralPath $destination) {
    Assert-NoLink $destination
    # Already there and right: nothing to do. Anything else is replaced.
    if ((Get-FileHash -LiteralPath $destination -Algorithm SHA256).Hash.ToLowerInvariant() -eq $file.Value) { continue }
    Remove-Item -LiteralPath $destination -Force
  }
  Copy-ArchiveFile $archive "$($pins.singBox.archiveRoot)/$($file.Name)" $destination
  Assert-Hash $destination $file.Value
}
Write-Host "The routing engine is in $engine"
