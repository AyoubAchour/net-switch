# Get-NetAdapter excludes non-present devices. Query the Net PnP class without
# -PresentOnly, and also recognize Wintun's instance namespace.
$ErrorActionPreference = 'Stop'
if ($env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_ENVIRONMENT -ne 'github-hosted') { throw 'Hosted Windows runners only.' }
@(
  Get-PnpDevice -Class Net | Where-Object {
    $_.FriendlyName -match 'NetSwitch|sing-tun' -or
    ($_.InstanceId -like 'SWD\Wintun\*' -and $_.FriendlyName -notlike 'TestISP*')
  } | ForEach-Object {
    $present = (Get-PnpDeviceProperty -InstanceId $_.InstanceId -KeyName 'DEVPKEY_Device_IsPresent').Data
    [pscustomobject]@{ name = $_.FriendlyName; instanceId = $_.InstanceId; status = $_.Status; present = [bool]$present }
  }
) | ConvertTo-Json -Compress
