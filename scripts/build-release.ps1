# Windows PowerShell 5.1. Downloads are cached, but their hashes are always checked.
[CmdletBinding()]
param([switch] $SkipInstaller)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
Set-StrictMode -Version Latest
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
Add-Type -AssemblyName System.IO.Compression.FileSystem
. (Join-Path $PSScriptRoot 'build-common.ps1')

$repoRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$dist = Join-Path $repoRoot 'dist'
$stage = Join-Path $dist 'stage'
$cache = Get-BuildCache $dist
$pins = Get-Content -LiteralPath (Join-Path $repoRoot 'packaging/versions.json') -Raw | ConvertFrom-Json
$package = Get-Content -LiteralPath (Join-Path $repoRoot 'package.json') -Raw | ConvertFrom-Json
if (-not $package.PSObject.Properties['version'] -or $package.version -notmatch '^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$') {
  throw 'package.json must contain a release version (for example 0.1.0). The build never invents or changes it.'
}
$version = $package.version

# This is the entire repository allowlist. Never copy the repository root.
$rootFiles = @(
  'launch.ps1', 'tray.ps1', 'server.mjs', 'package.json', 'LICENSE',
  'THIRD_PARTY_NOTICES.md', 'assets/net-switch.ico', 'engine/SHA256SUMS.txt', 'engine/LICENSE'
)
$trees = @('lib', 'ui', 'tools', 'licenses', 'docs')
$required = $rootFiles + $trees + @(
  'lib/tray.cs', 'ui/index.html', 'ui/app.js', 'ui/styles.css', 'ui/favicon.svg',
  'tools/stop.ps1', 'tools/restore-windows.mjs', 'tools/remove-autostart.mjs', 'licenses/lucide-ISC.txt', 'docs/user-guide.md',
  # Kept in the repository rather than downloaded: gnu.org refuses connections
  # from GitHub's runners. Its hash is still checked against the pin below.
  'licenses/GPL-3.0.txt'
)
$missing = @($required | Where-Object { -not (Test-Path -LiteralPath (Join-Path $repoRoot $_)) })
if ($missing.Count) { throw "Missing required packaging inputs: $($missing -join ', ')" }

$inputs = @(
  foreach ($relative in $rootFiles) {
    $file = Get-Item -LiteralPath (Join-Path $repoRoot $relative)
    Assert-NoLink $file.FullName
    Assert-NoLink $file.DirectoryName
    if ($file.PSIsContainer) { throw "Expected a file: $relative" }
    $file
  }
  foreach ($tree in $trees) {
    $files = @(Get-SafeFiles (Join-Path $repoRoot $tree))
    if (-not $files.Count) { throw "Required packaging directory is empty: $tree" }
    $files
  }
)

# Check the manifest against the app's independent engine verification pins.
$engineSums = @{}
foreach ($line in Get-Content -LiteralPath (Join-Path $repoRoot 'engine/SHA256SUMS.txt')) {
  if ($line -match '^\s*(?:#.*)?$') { continue }
  if ($line -notmatch '^([a-fA-F0-9]{64})\s+\*?([^\s]+)\s*$') { throw "Invalid engine checksum line: $line" }
  if ($engineSums.ContainsKey($Matches[2])) { throw "Duplicate engine checksum: $($Matches[2])" }
  $engineSums[$Matches[2]] = $Matches[1]
}
if ($engineSums.Count -ne 2) { throw 'engine/SHA256SUMS.txt must pin exactly sing-box.exe and libcronet.dll.' }
if (@($pins.singBox.files.PSObject.Properties).Count -ne 2 -or
    -not $pins.singBox.files.PSObject.Properties['sing-box.exe'] -or
    -not $pins.singBox.files.PSObject.Properties['libcronet.dll']) {
  throw 'versions.json must pin exactly sing-box.exe and libcronet.dll.'
}
foreach ($file in $pins.singBox.files.PSObject.Properties) {
  if ($engineSums[$file.Name] -ne $file.Value) { throw "Engine pin disagrees with engine/SHA256SUMS.txt: $($file.Name)" }
}

foreach ($directory in @($repoRoot, $dist, $cache)) {
  if (Test-Path -LiteralPath $directory) { Assert-NoLink $directory }
  else { New-Item -ItemType Directory -Path $directory | Out-Null }
}
# The native helper that reads the line meters, built from helper\ with the
# pinned Go (its own tests run first). It shares this download cache.
& (Join-Path $PSScriptRoot 'build-helper.ps1')
$helperExe = Join-Path $repoRoot 'helper\bin\netswitch-helper.exe'
Assert-NoLink $helperExe
# The tray icon as its own program, built with the C# compiler that comes with
# Windows, so the installed tray needs no PowerShell running.
& (Join-Path $PSScriptRoot 'build-tray.ps1')
$trayExe = Join-Path $repoRoot 'tray\bin\NetSwitchTray.exe'
Assert-NoLink $trayExe
$goZip = Get-Artifact $pins.go $cache
$nodeZip = Get-Artifact $pins.node $cache
$engineZip = Get-Artifact $pins.singBox $cache
$engineLicense = Get-Artifact $pins.licenses.singBox $cache
$cronetLicense = Get-Artifact $pins.licenses.cronetGo $cache
$wintunZip = Get-Artifact $pins.nativeSources.wintun $cache
$nativeLicenses = @(
  foreach ($pin in $pins.licenses.cronetNative) {
    if ([IO.Path]::IsPathRooted($pin.installPath) -or
        $pin.installPath -notmatch '^cronet-native/' -or
        @($pin.installPath -split '[/\\]' | Where-Object { $_ -in @('', '.', '..') }).Count) {
      throw "Invalid native license destination: $($pin.installPath)"
    }
    [PSCustomObject]@{ Pin = $pin; File = (Get-Artifact $pin $cache) }
  }
)

# Only this resolved build-owned directory is cleaned. Never touch data/ or design/.
if ([IO.Path]::GetFullPath($stage) -ne [IO.Path]::Combine($repoRoot, 'dist', 'stage')) {
  throw "Unsafe staging directory: $stage"
}
if (Test-Path -LiteralPath $stage) {
  $null = @(Get-SafeFiles $stage)
  Remove-Item -LiteralPath $stage -Recurse -Force
}
New-Item -ItemType Directory -Path $stage | Out-Null
foreach ($file in $inputs) {
  $relative = $file.FullName.Substring($repoRoot.Length + 1)
  $destination = Join-Path $stage $relative
  New-Item -ItemType Directory -Path (Split-Path $destination -Parent) -Force | Out-Null
  Copy-Item -LiteralPath $file.FullName -Destination $destination
}
Copy-ArchiveFile $nodeZip "$($pins.node.archiveRoot)/node.exe" (Join-Path $stage 'runtime/node.exe')
Copy-ArchiveFile $nodeZip "$($pins.node.archiveRoot)/LICENSE" (Join-Path $stage 'runtime/LICENSE')
Assert-Hash (Join-Path $stage 'runtime/LICENSE') $pins.licenses.node.sha256
Copy-Item -LiteralPath (Join-Path $stage 'runtime/LICENSE') -Destination (Join-Path $stage 'licenses/node-LICENSE.txt')
Copy-Item -LiteralPath $engineLicense -Destination (Join-Path $stage 'licenses/sing-box-LICENSE.txt')
Assert-Hash (Join-Path $stage 'licenses/node-LICENSE.txt') $pins.licenses.node.sha256
Assert-Hash (Join-Path $stage 'licenses/GPL-3.0.txt') $pins.licenses.gpl3.sha256
Assert-Hash (Join-Path $stage 'licenses/sing-box-LICENSE.txt') $pins.licenses.singBox.sha256
Copy-Item -LiteralPath $cronetLicense -Destination (Join-Path $stage 'licenses/cronet-go-LICENSE.txt')
Assert-Hash (Join-Path $stage 'licenses/cronet-go-LICENSE.txt') $pins.licenses.cronetGo.sha256
foreach ($license in $nativeLicenses) {
  $destination = Join-Path (Join-Path $stage 'licenses') $license.Pin.installPath
  New-Item -ItemType Directory -Path (Split-Path $destination -Parent) -Force | Out-Null
  Copy-Item -LiteralPath $license.File -Destination $destination
  Assert-Hash $destination $license.Pin.sha256
}
Copy-ArchiveFile $wintunZip $pins.licenses.wintun.archiveEntry (Join-Path $stage 'licenses/wintun-LICENSE.txt')
Assert-Hash (Join-Path $stage 'licenses/wintun-LICENSE.txt') $pins.licenses.wintun.sha256
foreach ($file in $pins.singBox.files.PSObject.Properties) {
  $destination = Join-Path $stage "engine/$($file.Name)"
  Copy-ArchiveFile $engineZip "$($pins.singBox.archiveRoot)/$($file.Name)" $destination
  Assert-Hash $destination $file.Value
}
# The helper has the Go runtime and golang.org/x/sys compiled in; both are under
# the Go authors' license, taken from the pinned Go archive.
$stagedHelper = Join-Path $stage 'helper/netswitch-helper.exe'
New-Item -ItemType Directory -Path (Split-Path $stagedHelper -Parent) -Force | Out-Null
Copy-Item -LiteralPath $helperExe -Destination $stagedHelper
Copy-ArchiveFile $goZip $pins.licenses.go.archiveEntry (Join-Path $stage 'licenses/go-LICENSE.txt')
Assert-Hash (Join-Path $stage 'licenses/go-LICENSE.txt') $pins.licenses.go.sha256
# Installed as <app>\tray\NetSwitchTray.exe, where launch.ps1 and stop.ps1 look for it.
$stagedTray = Join-Path $stage 'tray/NetSwitchTray.exe'
New-Item -ItemType Directory -Path (Split-Path $stagedTray -Parent) -Force | Out-Null
Copy-Item -LiteralPath $trayExe -Destination $stagedTray

# An inventory outside the installed tree makes an allowlist review straightforward.
$stageSums = @(Get-SafeFiles $stage | Sort-Object FullName | ForEach-Object {
  $relative = $_.FullName.Substring($stage.Length + 1).Replace('\', '/')
  '{0}  {1}' -f (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant(), $relative
})
[IO.File]::WriteAllLines((Join-Path $dist 'STAGE-SHA256SUMS.txt'), $stageSums, [Text.Encoding]::ASCII)
[IO.File]::WriteAllText((Join-Path $dist 'version.txt'), "$version`n", [Text.Encoding]::ASCII)
Write-Host "Staged Net Switch $version ($($stageSums.Count) files) at $stage"
if ($SkipInstaller) { return }

# Install the verified compiler privately in the build cache, without elevation or
# file associations. Reinstall it each build so an old local compiler is never used.
$innoInstaller = Get-Artifact $pins.innoSetup $cache
$compilerDir = Join-Path $cache "inno-$($pins.innoSetup.version)"
if (Test-Path -LiteralPath $compilerDir) { $null = @(Get-SafeFiles $compilerDir) }
$installArgs = '/CURRENTUSER /VERYSILENT /SUPPRESSMSGBOXES /NORESTART /SP- /NOICONS /TASKS="" /DIR="{0}"' -f $compilerDir
$process = Start-Process -FilePath $innoInstaller -ArgumentList $installArgs -WindowStyle Hidden -Wait -PassThru
if ($process.ExitCode -ne 0) { throw "Pinned Inno Setup installation failed (exit $($process.ExitCode))." }
$iscc = Join-Path $compilerDir 'ISCC.exe'
if (-not (Test-Path -LiteralPath $iscc -PathType Leaf)) { throw "Inno Setup did not install ISCC.exe at $iscc" }
$compilerVersion = & $iscc --version
if ($LASTEXITCODE -ne 0 -or $compilerVersion.Trim() -ne $pins.innoSetup.version) {
  throw "Expected Inno Setup $($pins.innoSetup.version), got '$compilerVersion'."
}
$installer = Join-Path $dist "NetSwitch-Setup-$version-x64.exe"
if (Test-Path -LiteralPath $installer) { Assert-NoLink $installer; Remove-Item -LiteralPath $installer -Force }
& $iscc --no-ide-signtools "/DAppVersion=$version" "/DStageDir=$stage" "/DOutputDir=$dist" (Join-Path $repoRoot 'packaging/NetSwitch.iss')
if ($LASTEXITCODE -ne 0) { throw "ISCC failed (exit $LASTEXITCODE)." }
if (-not (Test-Path -LiteralPath $installer -PathType Leaf)) { throw "ISCC did not produce $installer" }
$sum = '{0}  {1}' -f (Get-FileHash -LiteralPath $installer -Algorithm SHA256).Hash.ToLowerInvariant(), [IO.Path]::GetFileName($installer)
[IO.File]::WriteAllText((Join-Path $dist 'SHA256SUMS.txt'), "$sum`n", [Text.Encoding]::ASCII)
Write-Host "Built $installer"
