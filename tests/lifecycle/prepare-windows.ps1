param([Parameter(Mandatory=$true)][string]$Directory)
$ErrorActionPreference = 'Stop'
if ($env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_ENVIRONMENT -ne 'github-hosted') { throw 'Hosted runners only.' }
. "$PSScriptRoot/../../scripts/build-common.ps1"
Add-Type -AssemblyName System.IO.Compression.FileSystem
$arch = Get-NativeArchitecture
$pins = Get-Content "$PSScriptRoot/../../packaging/versions.json" -Raw | ConvertFrom-Json
$pin = (Get-ArchitecturePins $pins $arch).singBox
$cache = Get-BuildCache (Join-Path $PSScriptRoot '../../dist')
[IO.Directory]::CreateDirectory($cache) | Out-Null
$archive = Get-Artifact $pin $cache
$destination = Join-Path $Directory 'adapter'
[IO.Directory]::CreateDirectory($destination) | Out-Null
foreach ($file in $pin.files.PSObject.Properties) {
  Copy-ArchiveFile $archive "$($pin.archiveRoot)/$($file.Name)" (Join-Path $destination $file.Name)
  Assert-Hash (Join-Path $destination $file.Name) $file.Value
}
# The manifest is a test artifact generated from the pinned archive, not a
# substitute for the runtime installation ACL check.
$manifest = ($pin.files.PSObject.Properties | ForEach-Object { "$($_.Value)  $($_.Name)" }) -join "`n"
[IO.File]::WriteAllText((Join-Path $destination 'SHA256SUMS.txt'), "$manifest`n", [Text.UTF8Encoding]::new($false))
& "$PSScriptRoot/../windows/testisp/fetch-wintun.ps1" -Directory $Directory
icacls $Directory /setowner '*S-1-5-32-544' /T /Q
if ($LASTEXITCODE -ne 0) { throw 'Could not set installation ownership.' }
