param([ValidateSet('inspect', 'pnp', 'state', 'configure', 'reuse-route', 'withdraw', 'restore', 'block-direct', 'unblock-direct', 'clean')] [string] $Action)
$ErrorActionPreference = 'Stop'
if ($env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_ENVIRONMENT -ne 'github-hosted') { throw 'Hosted Windows runners only.' }
$admin = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $admin.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Administrator required.' }
if ($Action -eq 'pnp') {
  $devices = @(Get-PnpDevice -Class Net | Where-Object FriendlyName -like 'TestISP*' | ForEach-Object {
    $present = (Get-PnpDeviceProperty -InstanceId $_.InstanceId -KeyName 'DEVPKEY_Device_IsPresent').Data
    [pscustomobject]@{ instanceID = $_.InstanceId; present = [bool]$present }
  })
  ConvertTo-Json -InputObject $devices -Compress
  exit
}
if ($Action -eq 'inspect') {
  $route = Find-NetRoute -RemoteIPAddress '1.1.1.1' | Where-Object { $_.PSObject.Properties.Name -contains 'NextHop' } | Select-Object -First 1
  $adapter = Get-NetAdapter -InterfaceIndex $route.InterfaceIndex
  $ip = Get-NetIPAddress -InterfaceIndex $adapter.ifIndex -AddressFamily IPv4 | Where-Object AddressState -eq 'Preferred' | Select-Object -First 1
  if (-not $ip -or $adapter.Name -in @('TestISP', 'NetSwitch')) { throw 'No real uplink found.' }
  [pscustomobject]@{ index = $adapter.ifIndex; alias = $adapter.Name; address = $ip.IPAddress; gateway = $route.NextHop } | ConvertTo-Json -Compress
  exit
}
if ($Action -eq 'block-direct') {
  $index = [int]$env:TESTISP_UPLINK
  $adapter = Get-NetAdapter -InterfaceIndex $index
  if (-not $env:TESTISP_PROBE -or -not (Test-Path -LiteralPath $env:TESTISP_PROBE)) { throw 'Missing probe executable.' }
  New-NetFirewallRule -Name 'TestISP-direct-probe' -DisplayName 'TestISP direct probe only' -Direction Outbound -Action Block -Program $env:TESTISP_PROBE -InterfaceAlias $adapter.Name | Out-Null
} elseif ($Action -eq 'unblock-direct') {
  Get-NetFirewallRule -Name 'TestISP-direct-probe' -ErrorAction SilentlyContinue | Remove-NetFirewallRule
} elseif ($Action -eq 'clean') {
  $adapters = @(Get-NetAdapter -IncludeHidden | Where-Object Name -eq 'TestISP')
  $routes = @(Get-NetRoute | Where-Object InterfaceAlias -eq 'TestISP')
  $rules = @(Get-NetFirewallRule -Name 'TestISP-direct-probe' -ErrorAction SilentlyContinue)
  $devices = @(Get-PnpDevice -Class Net | Where-Object FriendlyName -like 'TestISP*')
  if ($adapters.Count -or $routes.Count -or $rules.Count -or $devices.Count) { throw "TestISP leftovers: $($adapters.Count) adapters, $($routes.Count) routes, $($rules.Count) firewall rules, $($devices.Count) PnP devices: $($devices | ConvertTo-Json -Compress)" }
} else {
  $index = [int]$env:TESTISP_INDEX
  $adapter = Get-NetAdapter -InterfaceIndex $index
  if ($index -le 0 -or $adapter.Name -ne 'TestISP') { throw 'Refusing to change an adapter other than TestISP.' }
  if ($Action -eq 'state') {
    [pscustomobject]@{ defaultRoute = [bool](Get-NetRoute -InterfaceIndex $index -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue) } | ConvertTo-Json -Compress
    exit
  }
  if ($Action -eq 'reuse-route') {
    New-NetRoute -InterfaceIndex $index -DestinationPrefix '198.19.128.2/32' -NextHop '0.0.0.0' -RouteMetric 1 -PolicyStore ActiveStore | Out-Null
    '{}'
    exit
  }
  if ($Action -eq 'configure') {
    Set-NetIPInterface -InterfaceIndex $index -AddressFamily IPv4 -AutomaticMetric Disabled -InterfaceMetric 5500 -NlMtuBytes 1500 -Dhcp Disabled
    Set-DnsClient -InterfaceIndex $index -RegisterThisConnectionsAddress $false
    New-NetIPAddress -InterfaceIndex $index -IPAddress '198.19.0.1' -PrefixLength 30 -AddressFamily IPv4 | Out-Null
    # New-NetIPAddress returns while duplicate-address detection is pending.
    $deadline = [DateTime]::UtcNow.AddSeconds(20)
    do {
      $address = Get-NetIPAddress -InterfaceIndex $index -IPAddress '198.19.0.1' -AddressFamily IPv4
      if ($address.AddressState -eq 'Preferred') { break }
      if ($address.AddressState -eq 'Duplicate') { throw 'TestISP address is duplicate.' }
      Start-Sleep -Milliseconds 200
    } while ([DateTime]::UtcNow -lt $deadline)
    if ($address.AddressState -ne 'Preferred') { throw "TestISP address never became ready: $($address | ConvertTo-Json -Compress)" }
  }
  if ($Action -eq 'withdraw') {
    Get-NetRoute -InterfaceIndex $index -DestinationPrefix '0.0.0.0/0' | Remove-NetRoute -Confirm:$false
  } elseif (-not (Get-NetRoute -InterfaceIndex $index -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue)) {
    New-NetRoute -InterfaceIndex $index -DestinationPrefix '0.0.0.0/0' -NextHop '0.0.0.0' -RouteMetric 5500 -PolicyStore ActiveStore | Out-Null
  }
}
'{}'
