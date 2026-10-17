# Fetch only this PC's engine into the source checkout. Never start it here.
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
    Remove-Item -LiteralPath $destination
  }
  Copy-ArchiveFile $zip "$($pin.archiveRoot)/$($file.Name)" $destination
  Assert-Hash $destination $file.Value
  Assert-PeArchitecture $destination $arch
}
Write-Host "Fetched the $arch engine into $engine"
