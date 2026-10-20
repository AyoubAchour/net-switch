# Real filesystem/hash checks with only the network and retry sleeps replaced.
# Runs in both Windows PowerShell 5.1 and PowerShell 7 in CI.
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
. "$PSScriptRoot/build-common.ps1"

$root = Join-Path ([IO.Path]::GetTempPath()) ("netswitch-download-test-" + [Guid]::NewGuid())
[IO.Directory]::CreateDirectory($root) | Out-Null
$good = [Text.Encoding]::UTF8.GetBytes('the pinned archive')
$bad = [Text.Encoding]::UTF8.GetBytes('a truncated or wrong response')
$sha = [Security.Cryptography.SHA256]::Create()
try { $hash = [BitConverter]::ToString($sha.ComputeHash($good)).Replace('-', '').ToLowerInvariant() } finally { $sha.Dispose() }
$pin = [PSCustomObject]@{ url = 'https://example.invalid/tool.zip'; sha256 = $hash }
$target = Join-Path $root 'tool.zip'
$partial = "$target.partial"

function Assert($Condition, [string] $Message) {
  if (-not $Condition) { throw $Message }
}
function Invoke-WebRequest {
  param([switch] $UseBasicParsing, [Uri] $Uri, [string] $OutFile, [int] $TimeoutSec, [string] $ErrorAction)
  $script:calls++
  Assert ($UseBasicParsing -and $Uri.Scheme -eq 'https' -and $TimeoutSec -eq 300 -and $ErrorAction -eq 'Stop') 'Transfer safeguards changed'
  Assert (-not (Test-Path -LiteralPath $OutFile)) 'Attempt reused a partial file'
  Assert (-not (Test-Path -LiteralPath $target)) 'Unverified target was published'
  $response = $script:responses[[Math]::Min($script:calls - 1, $script:responses.Count - 1)]
  if ($response -eq 'good') {
    [IO.File]::WriteAllBytes($OutFile, $good)
  } else {
    [IO.File]::WriteAllBytes($OutFile, $bad)
    if ($response -eq 'interrupted') { throw 'connection reset during transfer' }
  }
}
function Start-Sleep {
  param([int] $Seconds)
  $script:waits += $Seconds
}

$cases = @(
  @{ name = 'mismatch then success'; responses = @('bad', 'good'); calls = 2; waits = @(5) },
  @{ name = 'interrupted then success'; responses = @('interrupted', 'good'); calls = 2; waits = @(5) },
  @{ name = 'persistent mismatch'; responses = @('bad'); calls = 4; waits = @(5, 15, 30); fails = $true },
  @{ name = 'persistent interruption'; responses = @('interrupted'); calls = 4; waits = @(5, 15, 30); fails = $true },
  @{ name = 'verified cache hit'; responses = @('bad'); calls = 0; waits = @(); cached = 'good' },
  @{ name = 'corrupt cache restore'; responses = @('good'); calls = 1; waits = @(); cached = 'bad' },
  @{ name = 'abandoned partial'; responses = @('good'); calls = 1; waits = @(); partial = $true },
  @{ name = 'invalid pin'; responses = @('good'); calls = 0; waits = @(); fails = $true; invalidPin = $true }
)
try {
  foreach ($case in $cases) {
    foreach ($path in @($target, $partial)) {
      if (Test-Path -LiteralPath $path) { Remove-Item -LiteralPath $path }
    }
    $script:calls = 0
    $script:waits = @()
    $script:responses = $case.responses
    $pin.sha256 = $hash
    if ($case.ContainsKey('invalidPin')) { $pin.sha256 = 'not a hash' }
    if ($case.ContainsKey('cached')) {
      $data = if ($case.cached -eq 'good') { $good } else { $bad }
      [IO.File]::WriteAllBytes($target, $data)
    }
    if ($case.ContainsKey('partial')) { [IO.File]::WriteAllBytes($partial, $bad) }
    $expectedPin = $pin.sha256
    $failure = $null
    try { $result = Get-Artifact $pin $root } catch { $failure = $_.Exception.Message }
    $expectFailure = $case.ContainsKey('fails')
    Assert (($null -ne $failure) -eq $expectFailure) "$($case.name): unexpected result: $failure"
    Assert ($script:calls -eq $case.calls) "$($case.name): expected $($case.calls) attempts, got $script:calls"
    Assert (($script:waits -join ',') -eq ($case.waits -join ',')) "$($case.name): unexpected backoff"
    Assert ($pin.sha256 -ceq $expectedPin) "$($case.name): pin changed"
    Assert (-not (Test-Path -LiteralPath $partial)) "$($case.name): left a partial"
    if ($expectFailure) {
      Assert (-not (Test-Path -LiteralPath $target)) "$($case.name): accepted a rejected archive"
      if ($case.calls -eq 4) { Assert ($failure -match 'after 4 attempts') 'Missing attempt count' }
      if ($case.name -eq 'persistent mismatch') {
        Assert ($failure.Contains("Expected: $hash") -and $failure.Contains('Actual:')) 'Missing mismatch diagnostics'
      }
    } else {
      Assert ($result -eq $target) "$($case.name): wrong result path"
      Assert-Hash $result $hash
    }
    Write-Host "PASS: $($case.name) ($script:calls transfers)"
  }
  Write-Host "PASS: $($cases.Count) download cases under PowerShell $($PSVersionTable.PSVersion)"
} finally {
  # Only files in the unique directory created above are ours to remove.
  foreach ($path in @($target, $partial)) {
    if (Test-Path -LiteralPath $path) { Remove-Item -LiteralPath $path }
  }
  [IO.Directory]::Delete($root)
}
