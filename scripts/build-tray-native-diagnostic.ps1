if (-not $env:GITHUB_ACTIONS) { throw 'CI only' }
. (Join-Path $PSScriptRoot 'build-tray.ps1')
$nativeArguments = @($arguments | ForEach-Object {
  if ($_ -like '/win32manifest:*') { '/win32manifest:' + (Join-Path $PSScriptRoot 'tray-native-diagnostic.manifest') } else { $_ }
})
& $csc @nativeArguments
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
Write-Host 'DIAGNOSTIC ONLY: native ARM64 manifest opt-in'
