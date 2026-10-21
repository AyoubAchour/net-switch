# Hosted, read-only worker. Reuse loaded modules, never their network results.
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
if ($env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_ENVIRONMENT -ne 'github-hosted') { throw 'Hosted Windows runners only.' }
[Console]::InputEncoding = New-Object System.Text.UTF8Encoding($false)
[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)
$networkScript = Join-Path $PSScriptRoot '..\..\scripts\tun-test-network.ps1'
$pnpScript = Join-Path $PSScriptRoot 'pnp.ps1'
[Console]::Out.WriteLine((@{ ready = $true; pid = $PID } | ConvertTo-Json -Compress))
while ($null -ne ($line = [Console]::ReadLine())) {
  $request = $null
  try {
    $request = $line | ConvertFrom-Json
    if (($request.id -isnot [int] -and $request.id -isnot [long]) -or $request.id -le 0) { throw 'Invalid inspection request id.' }
    $started = [Diagnostics.Stopwatch]::StartNew()
    switch ($request.action) {
      'network' { $body = (& $networkScript -Action state | Out-String).Trim() }
      'pnp' { $body = (& $pnpScript | Out-String).Trim() }
      default { throw 'Read-only inspection action required.' }
    }
    [Console]::Out.WriteLine((@{ id = $request.id; body = $body; elapsedMs = $started.Elapsed.TotalMilliseconds } | ConvertTo-Json -Compress))
  } catch {
    [Console]::Out.WriteLine((@{ id = $request.id; error = $_.Exception.Message } | ConvertTo-Json -Compress))
  }
}
