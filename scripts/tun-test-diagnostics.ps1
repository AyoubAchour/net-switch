# Read-only failure evidence, run before cleanup on the disposable CI host.
param([int] $EnginePid, [int] $ClientPid, [string] $ResponderAddress, [int] $ResponderPort)
$ErrorActionPreference = 'Stop'
if ($env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_ENVIRONMENT -ne 'github-hosted') {
  throw 'TUN diagnostics are restricted to GitHub-hosted runners.'
}
function Emit($label, $value) {
  Write-Output ($label + ': ' + (ConvertTo-Json -InputObject $value -Depth 8 -Compress))
}
function SampleEngine {
  $sample = [ordered]@{ at = [DateTime]::UtcNow.ToString('o'); pid = $EnginePid; alive = $false }
  try {
    if ($EnginePid -le 0) { throw 'No valid engine.pid' }
    $engineProcess = Get-Process -Id $EnginePid -ErrorAction Stop
    $sample.alive = $true
    $sample.name = $engineProcess.ProcessName
    $sample.started = $engineProcess.StartTime.ToUniversalTime().ToString('o')
    $sample.cpuSeconds = $engineProcess.TotalProcessorTime.TotalSeconds
    $sample.threads = $engineProcess.Threads.Count
    $sample.workingSetBytes = $engineProcess.WorkingSet64
    $sample.privateBytes = $engineProcess.PrivateMemorySize64
  } catch { $sample.error = $_.Exception.Message }
  return $sample
}
$before = SampleEngine
Emit 'Engine process sample 1' $before
$elapsed = [Diagnostics.Stopwatch]::StartNew()
Start-Sleep -Milliseconds 2000
$after = SampleEngine
Emit 'Engine process sample 2' $after
if ($before.alive -and $after.alive -and $before.started -eq $after.started) {
  Emit 'Engine CPU delta' @{ seconds = $after.cpuSeconds - $before.cpuSeconds; elapsedMs = $elapsed.ElapsedMilliseconds }
}
try {
  $rows = @(Get-NetTCPConnection -ErrorAction Stop | Where-Object {
    $_.OwningProcess -gt 0 -and $_.OwningProcess -in @($ClientPid, $EnginePid)
  } | Select-Object OwningProcess, LocalAddress, LocalPort, RemoteAddress, RemotePort,
    @{Name='State'; Expression={$_.State.ToString()}},
    @{Name='toResponder'; Expression={$_.RemoteAddress -eq $ResponderAddress -and $_.RemotePort -eq $ResponderPort}})
  Emit 'TCP connections at failure' @{ at = [DateTime]::UtcNow.ToString('o'); rows = $rows }
} catch { Emit 'TCP diagnostics error' $_.Exception.Message }
try {
  $stats = @(Get-NetAdapterStatistics -Name NetSwitch -IncludeHidden -ErrorAction Stop |
    Select-Object Name, ReceivedBytes, SentBytes, ReceivedUnicastPackets, SentUnicastPackets,
      ReceivedDiscardedPackets, OutboundDiscardedPackets, ReceivedPacketErrors, OutboundPacketErrors)
  Emit 'NetSwitch adapter statistics' @{ at = [DateTime]::UtcNow.ToString('o'); adapters = $stats }
} catch { Emit 'NetSwitch statistics error' $_.Exception.Message }
