# Windows PowerShell 5.1. Builds helper\bin\netswitch-helper.exe, the small
# native program that reads the line meters and the connections that go around
# routing. It uses the Go toolchain pinned in packaging\versions.json, which is
# downloaded once into dist\cache and checked against its hash every time.
# NETSWITCH_CACHE can override dist\cache. Nothing is installed on the PC;
# downloads and Go's working files stay in the chosen cache.
#
#   powershell -NoProfile -ExecutionPolicy Bypass -File scripts\build-helper.ps1
#
# build-release.ps1 runs this too. Net Switch works without the helper (it
# falls back to PowerShell), so running from source doesn't need it.
[CmdletBinding()]
param([ValidateSet('x64', 'arm64')] [string] $Arch)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
Set-StrictMode -Version Latest
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
Add-Type -AssemblyName System.IO.Compression.FileSystem
. (Join-Path $PSScriptRoot 'build-common.ps1')
$hostArch = Get-NativeArchitecture
if (-not $Arch) { $Arch = $hostArch }
$goArch = if ($Arch -eq 'arm64') { 'arm64' } else { 'amd64' }

$repoRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$dist = Join-Path $repoRoot 'dist'
$cache = Get-BuildCache $dist
$helperDir = Join-Path $repoRoot 'helper'
$binDir = Join-Path $helperDir 'bin'
$output = Join-Path $binDir 'netswitch-helper.exe'
$pins = Get-Content -LiteralPath (Join-Path $repoRoot 'packaging/versions.json') -Raw | ConvertFrom-Json
$pin = $pins.go
if ($pin.version -notmatch '^\d+\.\d+\.\d+$') { throw "Invalid Go version pin: $($pin.version)" }
if ($pin.archiveRoot -ne [IO.Path]::GetFileName($pin.archiveRoot)) { throw "Invalid Go archive root: $($pin.archiveRoot)" }

foreach ($directory in @($repoRoot, $dist, $cache)) {
  if (Test-Path -LiteralPath $directory) { Assert-NoLink $directory }
  else { New-Item -ItemType Directory -Path $directory | Out-Null }
}
Assert-NoLink $helperDir
foreach ($path in @($binDir, $output)) {
  if (Test-Path -LiteralPath $path) { Assert-NoLink $path }
}

# Unpacked once. It goes to a temporary folder that is renamed when complete,
# so an interrupted unpack is never mistaken for a toolchain.
$zip = Get-Artifact $pin $cache
$toolchain = Join-Path $cache "go-$($pin.version)"
if (-not (Test-Path -LiteralPath $toolchain)) {
  $partial = "$toolchain.partial"
  if (Test-Path -LiteralPath $partial) {
    $null = @(Get-SafeFiles $partial)
    Remove-Item -LiteralPath $partial -Recurse -Force
  }
  Write-Host "Unpacking Go $($pin.version)"
  [IO.Compression.ZipFile]::ExtractToDirectory($zip, $partial)
  Rename-Item -LiteralPath $partial -NewName ([IO.Path]::GetFileName($toolchain))
}
Assert-NoLink $toolchain
$goRoot = Join-Path $toolchain $pin.archiveRoot
$go = Join-Path $goRoot 'bin\go.exe'
$gofmt = Join-Path $goRoot 'bin\gofmt.exe'
foreach ($tool in @($go, $gofmt)) {
  if (-not (Test-Path -LiteralPath $tool -PathType Leaf)) { throw "The unpacked Go toolchain has no $tool. Delete $toolchain and retry." }
}

$goHome = Join-Path $cache 'go-home'
$goEnv = [ordered]@{
  # Only the pinned toolchain: never another Go on this PC, or one Go downloads.
  GOROOT = $goRoot
  GOTOOLCHAIN = 'local'
  GOWORK = 'off'
  # Both targets use the pinned x64 toolchain; cross-compilation needs no C compiler.
  CGO_ENABLED = '0'
  GOOS = 'windows'
  GOARCH = $goArch
  GOAMD64 = 'v1'
  GOEXPERIMENT = $null
  # A build never changes go.mod or go.sum: every module must match go.sum.
  GOFLAGS = '-mod=readonly -p=2'
  GOMAXPROCS = '2'
  GOPROXY = 'https://proxy.golang.org,direct'
  GOSUMDB = 'sum.golang.org'
  # Everything Go writes stays in the cache. Go also keeps settings and usage
  # counters under %APPDATA%\go, so APPDATA points into the cache as well.
  GOENV = 'off'
  GOPATH = Join-Path $goHome 'gopath'
  GOMODCACHE = Join-Path $goHome 'modcache'
  GOCACHE = Join-Path $goHome 'buildcache'
  GOTMPDIR = Join-Path $goHome 'tmp'
  APPDATA = Join-Path $goHome 'appdata'
}
foreach ($directory in @($goHome, $goEnv.GOPATH, $goEnv.GOTMPDIR, $goEnv.APPDATA)) {
  if (Test-Path -LiteralPath $directory) { Assert-NoLink $directory }
  else { New-Item -ItemType Directory -Path $directory | Out-Null }
}

# Go reports progress on stderr, so only its exit code decides whether a step failed.
function Invoke-Go {
  & $go @args
  if ($LASTEXITCODE -ne 0) { throw "go $($args -join ' ') failed (exit $LASTEXITCODE)." }
}

# The settings above apply to this build only, and are put back afterwards.
$saved = @{}
foreach ($name in $goEnv.Keys) {
  $saved[$name] = [Environment]::GetEnvironmentVariable($name, 'Process')
  [Environment]::SetEnvironmentVariable($name, $goEnv[$name], 'Process')
}
try {
  $reported = & $go version
  if ($LASTEXITCODE -ne 0 -or $reported -ne "go version go$($pin.version) windows/amd64") {
    throw "Expected Go $($pin.version), got '$reported'. Delete $toolchain and retry."
  }
  Write-Host $reported

  # -C (run in helper\) must come straight after the command name.
  Invoke-Go mod download -C $helperDir
  Invoke-Go mod verify -C $helperDir
  $unformatted = @(& $gofmt -l $helperDir)
  if ($LASTEXITCODE -ne 0) { throw "gofmt failed (exit $LASTEXITCODE)." }
  if ($unformatted.Count) {
    throw "These Go files need formatting: $($unformatted -join ', ')`nRun: `"$gofmt`" -w `"$helperDir`""
  }
  Invoke-Go vet -C $helperDir ./...
  if ($Arch -eq $hostArch) {
    Invoke-Go test -C $helperDir ./...
  } else {
    Write-Host "Cross-compiling $Arch on $hostArch; helper tests run on the matching CI runner."
  }

  # The same source and toolchain always give the same file: no local paths,
  # build id or commit stamped into it, and no debug symbols.
  New-Item -ItemType Directory -Path $binDir -Force | Out-Null
  Invoke-Go build -C $helperDir -trimpath -buildvcs=false -ldflags '-s -w -buildid=' -o $output .
} finally {
  foreach ($name in $saved.Keys) { [Environment]::SetEnvironmentVariable($name, $saved[$name], 'Process') }
}

$built = Get-Item -LiteralPath $output
$sum = (Get-FileHash -LiteralPath $output -Algorithm SHA256).Hash.ToLowerInvariant()
Write-Host ("Built {0} ({1:N0} KB, SHA-256 {2})" -f $output.Substring($repoRoot.Length + 1), ($built.Length / 1KB), $sum)
