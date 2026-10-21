# No networking tests, adapters, engine or server may run here.
param([ValidateSet('vendor', 'verify', 'vet', 'build')] [string] $Action = 'vet', [string] $Go = 'go')
$ErrorActionPreference = 'Stop'
$env:GOTOOLCHAIN = 'local'
$env:GOMAXPROCS = '2'
$env:GOFLAGS = '-p=2'
$root = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
$module = Get-Content (Join-Path $root 'go.mod') -Raw
$pin = [regex]::Match($module, '(?m)^go\s+(\d+\.\d+\.\d+)\s*$')
if (-not $pin.Success) { throw 'The root go.mod must pin an exact Go version.' }
$version = $pin.Groups[1].Value
$Go = (Get-Command $Go -ErrorAction Stop).Source
if ((& $Go version) -notmatch "go$([regex]::Escape($version)) ") { throw "Use Go $version, pinned in the root go.mod." }
$arguments = switch ($Action) {
  'vendor' { @('mod', 'vendor') }
  'verify' { @('mod', 'verify') }
  'vet' { @('vet', './tests/windows/...') }
  'build' { @('build', '-p', '2', './tests/windows/...') }
}
$p = Start-Process -FilePath $Go -ArgumentList $arguments -WorkingDirectory $root -NoNewWindow -PassThru
$null = $p.Handle
$p.PriorityClass = 'Idle'
$p.WaitForExit()
exit $p.ExitCode
