# Temporary CI-only trace of the unchanged executable.
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$trayPath = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\tray\bin\NetSwitchTray.exe'))
$tracePath = Join-Path $env:RUNNER_TEMP 'tray-startup.etl'
$session = 'NetSwitchTrayStartup'
$launches = @()
& logman start $session -p Microsoft-Windows-DotNETRuntime 0x18 5 -o $tracePath -ets
if ($LASTEXITCODE -ne 0) { throw 'Could not start CLR trace' }
try {
  foreach ($phase in @('bad-arguments', 'absent-cold', 'absent-warm')) {
    $dataDir = Join-Path $env:RUNNER_TEMP ('netswitch-tray-profile-' + [Guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $dataDir | Out-Null
    $arguments = if ($phase -eq 'bad-arguments') { @('--data-dir') } else { @('-DataDir', ('"' + $dataDir + '"')) }
    $started = [DateTime]::UtcNow
    $watch = [Diagnostics.Stopwatch]::StartNew()
    $child = Start-Process -FilePath $trayPath -ArgumentList $arguments -WindowStyle Hidden -PassThru
    $null = $child.Handle
    $launches += @{ Phase = $phase; ProcessId = $child.Id; Started = $started }
    $seen = @{}
    try {
      do {
        $child.Refresh()
        if ($child.HasExited) { break }
        foreach ($module in $child.Modules) {
          if ($module.ModuleName -match 'clr|Drawing|Windows.Forms' -and -not $seen.ContainsKey($module.FileName)) {
            $seen[$module.FileName] = $true
            Write-Output "MODULE phase=$phase ms=$($watch.ElapsedMilliseconds) path=$($module.FileName)"
          }
        }
        if ($watch.Elapsed.TotalSeconds -ge 90) { throw "$phase exceeded 90 seconds" }
        Start-Sleep -Milliseconds 100
      } while ($true)
      Write-Output "PHASE phase=$phase pid=$($child.Id) started=$($started.ToString('o')) elapsedMs=$($watch.ElapsedMilliseconds) cpuMs=$($child.TotalProcessorTime.TotalMilliseconds) exit=$($child.ExitCode)"
      $logPath = Join-Path $dataDir 'tray.log'
      if (Test-Path -LiteralPath $logPath) { Get-Content -LiteralPath $logPath }
      $expected = if ($phase -eq 'bad-arguments') { 2 } else { 0 }
      if ($child.ExitCode -ne $expected) { throw "$phase returned $($child.ExitCode)" }
    } finally {
      if (-not $child.HasExited) { $child.Kill() }
      if (-not $child.WaitForExit(5000)) { throw 'Probe child survived cleanup' }
      $child.Dispose()
      # This is the fresh directory created above, wholly under RUNNER_TEMP.
      if (-not ([IO.Path]::GetFullPath($dataDir).StartsWith([IO.Path]::GetFullPath($env:RUNNER_TEMP) + '\'))) { throw 'Unexpected cleanup path' }
      Remove-Item -LiteralPath $dataDir -Recurse -Force
    }
  }
} finally {
  & logman stop $session -ets
}
$events = @(Get-WinEvent -Path $tracePath -Oldest)
foreach ($launch in $launches) {
  $own = @($events | Where-Object { $_.ProcessId -eq $launch.ProcessId })
  Write-Output "TRACE phase=$($launch.Phase) events=$($own.Count)"
  $previous = $launch.Started
  foreach ($event in $own) {
    $values = ($event.Properties | ForEach-Object { $_.Value }) -join ' | '
    $gap = ($event.TimeCreated.ToUniversalTime() - $previous).TotalMilliseconds
    if ($values -match 'NetSwitch|System.Windows.Forms|System.Drawing' -or $gap -gt 250) {
      $elapsed = ($event.TimeCreated.ToUniversalTime() - $launch.Started).TotalMilliseconds
      Write-Output "ETW phase=$($launch.Phase) ms=$([Math]::Round($elapsed)) gapMs=$([Math]::Round($gap)) id=$($event.Id) $values"
    }
    $previous = $event.TimeCreated.ToUniversalTime()
  }
}
