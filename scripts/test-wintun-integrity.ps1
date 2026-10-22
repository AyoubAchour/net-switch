param([ValidateRange(1, 1000)][int]$Repeats = 50)

$ErrorActionPreference = 'Stop'
if ($env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_ENVIRONMENT -ne 'github-hosted' -or
    $env:NETSWITCH_WINTUN_INTEGRITY -ne '1' -or $env:NETSWITCH_WINTUN_CI -ne '1') {
  throw 'The integrity diagnostic runs only on disposable hosted CI with explicit opt-in.'
}

# Each process executes all 12 matched positions, two fixed warm-ups per mode,
# eight measured streams and 64 MiB per stream. Repetition is exposure, never
# a replacement sample: the first unsuccessful process ends the job as failed.
# Leave eight minutes for a complete case, its teardown and the final summary.
$clock = [Diagnostics.Stopwatch]::StartNew()
$completed = 0
for ($repeat = 1; $repeat -le $Repeats; $repeat++) {
  if ($clock.Elapsed.TotalMinutes -ge 37 -and $completed -gt 0) { break }
  $env:NETSWITCH_WINTUN_INTEGRITY_REPEAT = [string]$repeat
  Write-Output "INTEGRITY_RUN_START repeat=$repeat requested=$Repeats commit=$env:GITHUB_SHA arch=$env:RUNNER_ARCH diagnostic=true"
  & ./bin/wintun.test.exe '-test.v' '-test.timeout=8m' '-test.run=^TestWintunPerformance$'
  $result = $LASTEXITCODE
  if ($result -ne 0) {
    Write-Output "INTEGRITY_RUN_FAILED repeat=$repeat completed=$completed requested=$Repeats exit=$result integrity-invalid comparison; no retry or replacement"
    exit $result
  }
  $completed++
  Write-Output "INTEGRITY_RUN_COMPLETE repeat=$repeat completed=$completed matched_pairs=$($completed * 12) elapsed_seconds=$([int]$clock.Elapsed.TotalSeconds)"
}
Write-Output "INTEGRITY_EXPOSURE completed=$completed requested=$Repeats matched_pairs=$($completed * 12) measured_streams=$($completed * 12 * 2 * 8) budget_limited=$($completed -lt $Repeats) diagnostic=true"
