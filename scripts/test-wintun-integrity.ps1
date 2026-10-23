param(
  [ValidateRange(1, 1000)][int]$Repeats = 50,
  [ValidateSet('proof', 'isolated', 'full')][string]$Scenario = 'proof',
  [ValidateSet('x64', 'arm64')][string]$Arch = 'x64',
  [switch]$PlanOnly
)

$ErrorActionPreference = 'Stop'
$Arch = $Arch.ToLowerInvariant()
$phases = @(Get-Content (Join-Path $PSScriptRoot 'wintun-integrity-sequence.json') -Raw | ConvertFrom-Json)
if ($Scenario -eq 'proof') {
  $phases = @($phases | Where-Object { $_.name -in @('capture-proof', 'proof') })
  $Repeats = 1 # The proof itself contains fixed matched samples; never retry it.
} else {
  $phases = @($phases | Where-Object { $_.name -notin @('capture-proof', 'proof') })
}
if ($Scenario -eq 'isolated') {
  $phases = @($phases | Where-Object name -eq 'performance-dll')
  $phases[0].timeoutSeconds = 480
}
$phases = @($phases | Where-Object { -not $_.arch -or $_.arch -eq $Arch })
$focus = if ($Scenario -eq 'isolated') { 'tcp_8_MBps' } else { '' }
$boundary = $env:NETSWITCH_WINTUN_INTEGRITY_BOUNDARY
if (-not $boundary) { $boundary = 'receive' }
if ($boundary -eq 'rotate') {
  $shard = 0
  if (-not [int]::TryParse($env:INTEGRITY_SHARD, [ref]$shard) -or $shard -lt 1 -or $shard -gt 20) {
    throw 'Boundary rotation requires an integer INTEGRITY_SHARD between 1 and 20.'
  }
  $boundary = @('receive', 'ingress', 'echo', 'output', 'send', 'host')[($shard - 1) % 6]
}
if ($boundary -notin @('receive', 'ingress', 'echo', 'output', 'send', 'host', 'all')) {
  throw "Unknown integrity boundary: $boundary"
}
# Read-only plan/parity tests: no executable or adapter is used.
if ($PlanOnly) {
  [pscustomobject]@{ scenario = $Scenario; arch = $Arch; focus = $focus; boundary = $boundary; repeats = $Repeats; phases = $phases; calibrationAfterExposure = ($Scenario -ne 'proof') } | ConvertTo-Json -Depth 8
  return
}
if ($env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_ENVIRONMENT -ne 'github-hosted' -or
    $env:NETSWITCH_WINTUN_INTEGRITY -ne '1' -or $env:NETSWITCH_WINTUN_CI -ne '1') {
  throw 'The integrity diagnostic runs only on disposable hosted CI with explicit opt-in.'
}
if ($env:RUNNER_ARCH.ToLowerInvariant() -ne $Arch) { throw 'Requested architecture does not match the runner.' }
if ($PSVersionTable.PSVersion.Major -lt 7) { throw 'Run this hosted diagnostic with pwsh (PowerShell 7).' }

# Preserve the normal job's fresh process per phase and its driver/host
# lifetime. Full performance keeps one adapter per pair across all five
# metrics. Never reset the driver between cycles or retry a failed cycle.
$clock = [Diagnostics.Stopwatch]::StartNew()
$completed = 0
$lastSeconds = 0
$calibrationSeconds = if ($Scenario -eq 'proof') { 0 } elseif ($boundary -eq 'all') { 1200 } else { 180 }
$budgetSeconds = 45 * 60 - $calibrationSeconds
$runExit = 0
$keys = @('NETSWITCH_WINTUN_CI', 'NETSWITCH_WINTUN_INTEGRITY', 'NETSWITCH_WINTUN_INTEGRITY_TRACE',
  'NETSWITCH_WINTUN_INTEGRITY_BOUNDARY',
  'NETSWITCH_WINTUN_INTEGRITY_FOCUS', 'NETSWITCH_WINTUN_INTEGRITY_REPEAT',
  'NETSWITCH_WINTUN_INTEGRITY_SCENARIO', 'NETSWITCH_WINTUN_INTEGRITY_PHASE',
  'NETSWITCH_WINTUN_REFERENCE', 'NETSWITCH_WINTUN_PROFILE')
$saved = @{}
foreach ($key in $keys) { $saved[$key] = [Environment]::GetEnvironmentVariable($key, 'Process') }
try {
  $env:NETSWITCH_WINTUN_INTEGRITY_BOUNDARY = $boundary
  $env:NETSWITCH_WINTUN_INTEGRITY_TRACE = '1'
  $env:NETSWITCH_WINTUN_INTEGRITY_SCENARIO = $Scenario
  for ($repeat = 1; $repeat -le $Repeats; $repeat++) {
    # Reserve a complete next cycle using the last duration with headroom.
    # An overrun fails the partial cycle explicitly; it is never counted.
    $reserve = if ($Scenario -eq 'isolated') { 480 } else { [Math]::Max(1200, $lastSeconds * 1.5) }
    if ($completed -gt 0 -and ($budgetSeconds - $clock.Elapsed.TotalSeconds) -lt $reserve) { break }
    $cycleStart = $clock.Elapsed.TotalSeconds
    $env:NETSWITCH_WINTUN_INTEGRITY_REPEAT = [string]$repeat
    $failed = 0
    $outcomes = @{}
    Write-Output "INTEGRITY_RUN_START scenario=$Scenario boundary=$boundary repeat=$repeat requested=$Repeats shard=$env:INTEGRITY_SHARD commit=$env:GITHUB_SHA arch=$Arch diagnostic=true"
    foreach ($phase in $phases) {
      $name = $phase.name
      if (($failed -ne 0 -and -not $phase.runAfterFailure) -or
          ($phase.requiresSuccess -and $outcomes[$phase.requiresSuccess] -ne 'passed')) {
        $outcomes[$name] = 'skipped_after_failure'
        Write-Output "INTEGRITY_PHASE_SKIPPED scenario=$Scenario repeat=$repeat phase=$name reason=normal_workflow_failure_dependency"
        continue
      }
      $remaining = [int][Math]::Floor($budgetSeconds - $clock.Elapsed.TotalSeconds - 15)
      if ($remaining -le 0) {
        Write-Output "INTEGRITY_RUN_FAILED scenario=$Scenario repeat=$repeat phase=$name verdict=diagnostic_incomplete reason=budget_exhausted incomplete=true"
        exit 1
      }
      $seconds = [int][Math]::Min($phase.timeoutSeconds, $remaining)
      $env:NETSWITCH_WINTUN_CI = if ($phase.ci -eq '0') { '0' } else { '1' }
      $env:NETSWITCH_WINTUN_INTEGRITY = if ($phase.diagnostic) { '1' } else { '0' }
      $env:NETSWITCH_WINTUN_INTEGRITY_FOCUS = $focus
      $env:NETSWITCH_WINTUN_REFERENCE = if ($phase.reference) { $phase.reference } else { 'dll' }
      $env:NETSWITCH_WINTUN_PROFILE = if ($phase.profile) { $phase.profile } else { '' }
      $env:NETSWITCH_WINTUN_INTEGRITY_PHASE = $name
      $arguments = @($phase.args)
      if ($phase.kind -eq 'test') { $arguments += @('-test.v', "-test.timeout=$($seconds)s") }
      if ($phase.kind -eq 'go-test') { $arguments = @($arguments[0], "-timeout=$($seconds)s") + $arguments[1..($arguments.Count-1)] }
      Write-Output "INTEGRITY_PHASE_START scenario=$Scenario repeat=$repeat phase=$name diagnostic=$env:NETSWITCH_WINTUN_INTEGRITY program=$($phase.program) args=$($arguments -join ' ')"
      # These arguments contain no spaces; Start-Process therefore preserves
      # each selector. Pin the process handle before waiting (including a
      # failed exit), and bound the whole process, not only Go's test timer.
      $program = $phase.program
      if ($phase.proof) {
        $arguments = @('scripts/run-native-proof.mjs', $phase.proof, $program) + $arguments
        $program = 'node'
      }
      $process = Start-Process -FilePath $program -ArgumentList $arguments -WorkingDirectory $PWD.Path -NoNewWindow -PassThru
      $null = $process.Handle
      Write-Output "INTEGRITY_PHASE_PROCESS scenario=$Scenario repeat=$repeat phase=$name pid=$($process.Id)"
      if (-not $process.WaitForExit(($seconds + 15) * 1000)) {
        $process.Kill($true) # This phase's tree only, on the disposable runner.
        $null = $process.WaitForExit(5000)
        $result = 124
        Write-Output "INTEGRITY_PHASE_TIMEOUT scenario=$Scenario repeat=$repeat phase=$name verdict=diagnostic_timeout seconds=$seconds incomplete=true"
      } else {
        $process.WaitForExit()
        $result = $process.ExitCode
        if ($null -eq $result) { throw "Missing exit code for phase $name" }
      }
      if ($result -ne 0) {
        if ($failed -eq 0) { $failed = $result }
        $outcomes[$name] = 'failed'
        Write-Output "INTEGRITY_PHASE_FAILED scenario=$Scenario repeat=$repeat phase=$name exit=$result"
      } else {
        $outcomes[$name] = 'passed'
        Write-Output "INTEGRITY_PHASE_COMPLETE scenario=$Scenario repeat=$repeat phase=$name"
      }
    }
    if ($failed -ne 0) {
      Write-Output "INTEGRITY_RUN_FAILED scenario=$Scenario repeat=$repeat completed=$completed requested=$Repeats exit=$failed verdict=test_failed; consult structured diagnostic verdicts; no retry or replacement"
      $runExit = $failed
      break # Stop exposure without retrying; still measure this job's overhead.
    }
    $completed++
    $lastSeconds = $clock.Elapsed.TotalSeconds - $cycleStart
    Write-Output "INTEGRITY_RUN_COMPLETE scenario=$Scenario repeat=$repeat completed=$completed elapsed_seconds=$([int]$clock.Elapsed.TotalSeconds)"
  }
  if ($Scenario -eq 'proof') {
    Write-Output "INTEGRITY_JOB_COMPLETE scenario=proof shard=$env:INTEGRITY_SHARD exit=$runExit; job-wide verdict follows in INTEGRITY_SUMMARY"
    exit $runExit
  }
  $inprocessPairs = if ($Scenario -eq 'full') { $completed * 12 } else { 0 }
  $measuredStreams = $completed * $(if ($Scenario -eq 'full') { 432 } else { 192 })
  Write-Output "INTEGRITY_OBSERVED_EXPOSURE scenario=$Scenario boundary=$boundary shard=$env:INTEGRITY_SHARD completed=$completed requested=$Repeats dll_tcp8_pairs=$($completed * 12) inprocess_tcp8_pairs=$inprocessPairs measured_tcp_streams=$measuredStreams budget_limited=$($completed -lt $Repeats) eligibility=pending_calibration"
  # Calibrate AFTER the original sequence, with the selected boundary and all
  # implementations used in this job. This cannot reset its pre-exposure state.
  $env:NETSWITCH_WINTUN_CI = '1'
  $env:NETSWITCH_WINTUN_INTEGRITY = '1'
  $env:NETSWITCH_WINTUN_INTEGRITY_PHASE = 'calibration'
  Write-Output "INTEGRITY_CALIBRATION_START scenario=$Scenario boundary=$boundary seconds=$calibrationSeconds"
  $calibration = Start-Process -FilePath './bin/wintun.test.exe' -ArgumentList @('-test.run=^TestWintunIntegrityProof$', '-test.v', "-test.timeout=$($calibrationSeconds)s") -WorkingDirectory $PWD.Path -NoNewWindow -PassThru
  $null = $calibration.Handle
  if (-not $calibration.WaitForExit(($calibrationSeconds + 15) * 1000)) {
    $calibration.Kill($true)
    $null = $calibration.WaitForExit(5000)
    Write-Output 'INTEGRITY_PHASE_TIMEOUT phase=calibration verdict=diagnostic_incomplete'
    exit 1
  }
  $calibration.WaitForExit()
  if ($null -eq $calibration.ExitCode) { throw 'Missing calibration exit code' }
  if ($calibration.ExitCode -ne 0) { $runExit = $calibration.ExitCode }
  Write-Output "INTEGRITY_JOB_COMPLETE scenario=$Scenario shard=$env:INTEGRITY_SHARD exit=$runExit; job-wide verdict follows in INTEGRITY_SUMMARY"
  exit $runExit
} finally {
  foreach ($key in $keys) { [Environment]::SetEnvironmentVariable($key, $saved[$key], 'Process') }
}
