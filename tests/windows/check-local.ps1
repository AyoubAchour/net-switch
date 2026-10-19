# No networking tests, adapters, engine or server may run here.
param([ValidateSet('vendor', 'verify', 'vet', 'build')] [string] $Action = 'vet', [string] $Go = 'go')
$ErrorActionPreference = 'Stop'
$env:GOTOOLCHAIN = 'local'
$env:GOMAXPROCS = '2'
$env:GOFLAGS = '-p=2'
$root = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
$pins = Get-Content (Join-Path $root 'packaging/versions.json') -Raw | ConvertFrom-Json
$Go = (Get-Command $Go -ErrorAction Stop).Source
if ((& $Go version) -notmatch "go$([regex]::Escape($pins.go.version)) ") { throw 'Use the Go version pinned in packaging/versions.json.' }
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
