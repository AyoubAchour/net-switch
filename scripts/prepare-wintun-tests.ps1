# Runs only on disposable hosted CI. The binary is extracted unchanged directly
# beside the test executable; the production loader verifies its hash again.
$ErrorActionPreference = 'Stop'
if ($env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_ENVIRONMENT -ne 'github-hosted') {
  throw 'Wintun integration setup is restricted to GitHub-hosted runners.'
}
$pins = Get-Content packaging/versions.json -Raw | ConvertFrom-Json
$pin = $pins.nativeSources.wintun
$arch = if ($env:RUNNER_ARCH -eq 'ARM64') { 'arm64' } else { 'amd64' }
$expected = if ($arch -eq 'arm64') { $pin.embeddedArm64Sha256 } else { $pin.embeddedAmd64Sha256 }
. "$PSScriptRoot/build-common.ps1"
$cache = Get-BuildCache (Join-Path $PSScriptRoot '../dist')
[IO.Directory]::CreateDirectory($cache) | Out-Null
$archive = Get-Artifact $pin $cache
Add-Type -AssemblyName System.IO.Compression.FileSystem
$zip = [IO.Compression.ZipFile]::OpenRead($archive)
try {
  $entry = $zip.GetEntry("wintun/bin/$arch/wintun.dll")
  if (-not $entry) { throw "Missing $arch DLL" }
  [IO.Compression.ZipFileExtensions]::ExtractToFile($entry, (Join-Path $PWD 'bin/wintun.dll'), $true)
} finally { $zip.Dispose() }
Assert-Hash 'bin/wintun.dll' $expected
