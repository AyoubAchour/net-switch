# No networking tests, adapters, engine or server may run here.
param([ValidateSet('tidy', 'vendor', 'verify', 'vet', 'unit')] [string] $Action = 'unit')
$ErrorActionPreference = 'Stop'
$env:GOTOOLCHAIN = 'local'
$env:GOMAXPROCS = '2'
$env:GOFLAGS = '-p=2'
$env:GOCACHE = 'C:\Users\Ayoub\Desktop\net-switch\dist\cache\go-home\buildcache'
$env:GOPATH = 'C:\Users\Ayoub\Desktop\net-switch\dist\cache\go-home\gopath'
$env:GOMODCACHE = 'C:\Users\Ayoub\Desktop\net-switch\dist\cache\go-home\modcache'
$go = 'C:\Users\Ayoub\Desktop\net-switch\dist\cache\go-1.27.2\go\bin\go.exe'
$arguments = switch ($Action) {
  'tidy' { @('mod', 'tidy') }
  'vendor' { @('mod', 'vendor') }
  'verify' { @('mod', 'verify') }
  'vet' { @('vet', './tests/windows/...') }
  'unit' { @('test', './tests/windows/...') }
}
$p = Start-Process -FilePath $go -ArgumentList $arguments -NoNewWindow -PassThru
$null = $p.Handle
$p.PriorityClass = 'Idle'
$p.WaitForExit()
exit $p.ExitCode
