# CI only: binaries are never downloaded to the owner's live machine.
param([Parameter(Mandatory=$true)] [string] $Directory)
$ErrorActionPreference = 'Stop'
if ($env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_ENVIRONMENT -ne 'github-hosted') {
  throw 'Wintun download is restricted to disposable GitHub-hosted runners.'
}
. "$PSScriptRoot/../../../scripts/build-common.ps1"
$arch = Get-NativeArchitecture
$pin = (Get-Content "$PSScriptRoot/../../../packaging/versions.json" -Raw | ConvertFrom-Json).nativeSources.wintun
$directoryPath = [IO.Path]::GetFullPath($Directory)
[IO.Directory]::CreateDirectory($directoryPath) | Out-Null
$cache = Get-BuildCache (Join-Path $PSScriptRoot '../../../dist')
[IO.Directory]::CreateDirectory($cache) | Out-Null
$archive = Get-Artifact $pin $cache
Add-Type -AssemblyName System.IO.Compression.FileSystem
$zip = [IO.Compression.ZipFile]::OpenRead($archive)
try {
  $machine = if ($arch -eq 'x64') { 'amd64' } else { 'arm64' }
  foreach ($pair in @(@("wintun/bin/$machine/wintun.dll", 'wintun.dll'), @('wintun/LICENSE.txt', 'WINTUN-LICENSE.txt'))) {
    $entry = $zip.GetEntry($pair[0])
    if (-not $entry) { throw "Missing $($pair[0])" }
    [IO.Compression.ZipFileExtensions]::ExtractToFile($entry, (Join-Path $directoryPath $pair[1]), $true)
  }
} finally { $zip.Dispose() }
$dll = Join-Path $directoryPath 'wintun.dll'
$expected = if ($arch -eq 'x64') { $pin.embeddedAmd64Sha256 } else { $pin.embeddedArm64Sha256 }
$actual = (Get-FileHash -LiteralPath $dll -Algorithm SHA256).Hash
if ($actual -ne $expected) { throw "Wintun $arch DLL hash mismatch." }
$signature = Get-AuthenticodeSignature -LiteralPath $dll
if ($signature.Status -ne 'Valid') { throw "Wintun signature: $($signature.Status) $($signature.StatusMessage)" }
Write-Output "Verified Wintun $($pin.version) $arch SHA256=$actual signer=$($signature.SignerCertificate.Subject)"
