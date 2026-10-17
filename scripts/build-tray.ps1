# Windows PowerShell 5.1. Builds tray\bin\NetSwitchTray.exe, the tray icon as a
# small program of its own, from lib\tray.cs and lib\tray-main.cs. It uses the
# C# compiler that comes with Windows (part of .NET Framework 4), the same one
# Add-Type uses for tray.ps1 and the tray tests, so nothing is downloaded or
# installed.
#
#   powershell -NoProfile -ExecutionPolicy Bypass -File scripts\build-tray.ps1
#
# build-release.ps1 runs this too. Without the program, launch.ps1 runs
# tray.ps1, which compiles the same code each time it starts.
#
# This compiler can't make a byte-for-byte repeatable file: it has no
# /deterministic, so each build stamps its own time and module ID and gets a
# different SHA-256. What is fixed is the input: the source in this repository,
# built by the compiler Windows ships, with no local paths or debug file inside.
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot 'build-common.ps1')

$repoRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$trayDir = Join-Path $repoRoot 'tray'
$binDir = Join-Path $trayDir 'bin'
$output = Join-Path $binDir 'NetSwitchTray.exe'
$sources = @(
  (Join-Path $repoRoot 'lib\tray.cs'),
  (Join-Path $repoRoot 'lib\tray-main.cs')
)
$icon = Join-Path $repoRoot 'assets\net-switch.ico'
$manifest = Join-Path $repoRoot 'lib\tray.manifest'
# The 64-bit .NET Framework 4 compiler. It knows C# up to version 5, which is
# why lib\tray.cs stays at C# 5.
$csc = Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
if ((Get-NativeArchitecture) -eq 'arm64') {
  $csc = Join-Path $env:WINDIR 'Microsoft.NET\FrameworkArm64\v4.0.30319\csc.exe'
}
if (-not (Test-Path -LiteralPath $csc -PathType Leaf)) {
  throw "The C# compiler that comes with Windows wasn't found at $csc. It is part of .NET Framework 4, which Windows 10 and 11 include."
}

foreach ($file in $sources + @($icon, $manifest)) { Assert-NoLink $file }
foreach ($path in @($repoRoot, $trayDir, $binDir, $output)) {
  if (Test-Path -LiteralPath $path) { Assert-NoLink $path }
}
New-Item -ItemType Directory -Path $binDir -Force | Out-Null
Write-Host "C# compiler $((Get-Item -LiteralPath $csc).VersionInfo.ProductVersion)"

# /noconfig leaves out the compiler's long list of default references, so the
# program references exactly what tray.ps1 gives Add-Type, plus System.dll.
# Warnings fail the build, as they fail Add-Type. The sources are UTF-8 without
# a byte order mark, which is said outright rather than left to this PC's code
# page. No debug file is written, so no local path ends up in the program.
# References are full paths into the framework folder: a bare name is looked
# up in the current folder first, where a stray DLL could stand in for one.
$framework = Split-Path $csc -Parent
$references = @('System.dll', 'System.Drawing.dll', 'System.Windows.Forms.dll', 'System.Net.Http.dll', 'System.Web.Extensions.dll') |
  ForEach-Object {
    $reference = Join-Path $framework $_
    if (-not (Test-Path -LiteralPath $reference -PathType Leaf)) { throw "The .NET Framework assembly $reference is missing." }
    "/reference:$reference"
  }
$arguments = @(
  '/nologo', '/noconfig', '/utf8output', '/codepage:65001', '/langversion:5',
  '/target:winexe', '/platform:anycpu', '/optimize+', '/debug-', '/warn:4', '/warnaserror+'
) + $references + @(
  "/win32icon:$icon", "/win32manifest:$manifest", "/out:$output"
) + $sources
# AnyCPU (without Prefer32Bit) uses the native CLR on Windows 11 ARM64 with
# .NET Framework 4.8.1, as well as the x64 CLR on x64 Windows.
$messages = @(& $csc @arguments)
if ($LASTEXITCODE -ne 0) {
  throw ("The tray program didn't build (csc exit $LASTEXITCODE):`n" + ($messages -join "`n") +
    "`nIf this program is running (its tray icon is showing), quit it first: Windows won't replace a running program.")
}

$built = Get-Item -LiteralPath $output
Assert-PeArchitecture $output 'AnyCPU'
$sum = (Get-FileHash -LiteralPath $output -Algorithm SHA256).Hash.ToLowerInvariant()
Write-Host ("Built {0} ({1:N0} KB, SHA-256 {2})" -f $output.Substring($repoRoot.Length + 1), ($built.Length / 1KB), $sum)
