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
Add-Type -AssemblyName System.IO.Compression
$client = [System.Net.Http.HttpClient]::new()
try {
  $data = $client.GetByteArrayAsync($pin.url).GetAwaiter().GetResult()
  $sha = [Security.Cryptography.SHA256]::Create()
  try { $actual = [Convert]::ToHexString($sha.ComputeHash($data)).ToLowerInvariant() } finally { $sha.Dispose() }
  if ($actual -ne $pin.sha256) { throw 'Wintun archive hash mismatch.' }
  $memory = [IO.MemoryStream]::new($data, $false)
  $zip = [IO.Compression.ZipArchive]::new($memory, [IO.Compression.ZipArchiveMode]::Read)
  try {
    $entry = $zip.GetEntry("wintun/bin/$arch/wintun.dll")
    if (-not $entry) { throw "Missing $arch DLL" }
    $source = $entry.Open()
    $target = [IO.File]::Create((Join-Path $PWD 'bin/wintun.dll'))
    try { $source.CopyTo($target) } finally { $target.Dispose(); $source.Dispose() }
  } finally { $zip.Dispose(); $memory.Dispose() }
  if ((Get-FileHash bin/wintun.dll -Algorithm SHA256).Hash.ToLowerInvariant() -ne $expected) { throw 'Wintun DLL hash mismatch.' }
} finally { $client.Dispose() }
