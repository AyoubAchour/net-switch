param([ValidateSet('allow', 'ipv6', 'capture', 'clean')] [string] $Action)
$ErrorActionPreference = 'Stop'
if ($env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_ENVIRONMENT -ne 'github-hosted') { throw 'Hosted Windows runners only.' }
$names = @('NetSwitch-acceptance-client-udp', 'NetSwitch-acceptance-gateway-udp', 'NetSwitch-acceptance-engine-udp', 'NetSwitch-acceptance-probe-udp')
if ($Action -eq 'ipv6') {
  $primary = [int]$env:ACCEPTANCE_UPLINK
  $virtual = [int]$env:ACCEPTANCE_TESTISP
  if ($primary -le 0 -or $virtual -le 0 -or (Get-NetAdapter -InterfaceIndex $virtual).Name -ne 'TestISP') { throw 'Missing harness interface identities.' }
  foreach ($address in @('2001:db8:18::1', '2001:db8:19::1')) {
    if (Get-NetIPAddress -IPAddress $address -ErrorAction SilentlyContinue) { throw "Address already exists: $address" }
  }
  New-NetIPAddress -InterfaceIndex $primary -IPAddress '2001:db8:18::1' -PrefixLength 128 -AddressFamily IPv6 -SkipAsSource $true -PolicyStore ActiveStore | Out-Null
  New-NetIPAddress -InterfaceIndex $virtual -IPAddress '2001:db8:19::1' -PrefixLength 64 -AddressFamily IPv6 -PolicyStore ActiveStore | Out-Null
  Set-NetIPInterface -InterfaceIndex $virtual -AddressFamily IPv6 -AutomaticMetric Disabled -InterfaceMetric 5500 -NlMtuBytes 1500
  New-NetRoute -InterfaceIndex $virtual -DestinationPrefix '::/0' -NextHop '::' -RouteMetric 5500 -PolicyStore ActiveStore | Out-Null
  New-NetRoute -InterfaceIndex $virtual -DestinationPrefix '198.19.128.2/32' -NextHop '0.0.0.0' -RouteMetric 1 -PolicyStore ActiveStore | Out-Null
  New-NetRoute -InterfaceIndex $virtual -DestinationPrefix '2001:db8:198::2/128' -NextHop '::' -RouteMetric 1 -PolicyStore ActiveStore | Out-Null
  $deadline = [DateTime]::UtcNow.AddSeconds(20)
  do {
    $addresses = @(Get-NetIPAddress -IPAddress @('2001:db8:18::1', '2001:db8:19::1') -AddressFamily IPv6)
    if ($addresses.Count -eq 2 -and @($addresses | Where-Object AddressState -ne 'Preferred').Count -eq 0) { break }
    Start-Sleep -Milliseconds 200
  } while ([DateTime]::UtcNow -lt $deadline)
  if ($addresses.Count -ne 2 -or @($addresses | Where-Object AddressState -ne 'Preferred').Count) { throw "IPv6 targets not ready: $($addresses | ConvertTo-Json -Compress)" }
} elseif ($Action -eq 'capture') {
  $virtual = [int]$env:ACCEPTANCE_TESTISP
  if ($virtual -le 0 -or (Get-NetAdapter -InterfaceIndex $virtual).Name -ne 'TestISP') { throw 'Missing TestISP identity.' }
  foreach ($prefix in @('198.19.128.2/32', '2001:db8:198::2/128')) {
    Get-NetRoute -InterfaceIndex $virtual -DestinationPrefix $prefix | Remove-NetRoute -Confirm:$false
    if (Get-NetRoute -InterfaceIndex $virtual -DestinationPrefix $prefix -ErrorAction SilentlyContinue) { throw "Direct target route remained: $prefix" }
  }
} elseif ($Action -eq 'allow') {
  $programs = @($env:ACCEPTANCE_CLIENT, $env:ACCEPTANCE_GATEWAY, $env:ACCEPTANCE_ENGINE, $env:ACCEPTANCE_UDP_PROBE)
  for ($i = 0; $i -lt $programs.Count; $i++) {
    if (-not (Test-Path -LiteralPath $programs[$i])) { throw 'Missing test program.' }
    if (Get-NetFirewallRule -Name $names[$i] -ErrorAction SilentlyContinue) { throw 'Test firewall rule already exists.' }
    # A STUN response from a third port is deliberately unsolicited. Allow only
    # these programs and controlled source addresses, never all UDP.
    New-NetFirewallRule -Name $names[$i] -DisplayName $names[$i] -Direction Inbound -Action Allow -Program $programs[$i] -Protocol UDP -RemoteAddress @($env:ACCEPTANCE_TARGET, '198.19.128.2', '2001:db8:198::2') | Out-Null
  }
} else {
  foreach ($name in $names) { Get-NetFirewallRule -Name $name -ErrorAction SilentlyContinue | Remove-NetFirewallRule }
  foreach ($name in $names) { if (Get-NetFirewallRule -Name $name -ErrorAction SilentlyContinue) { throw "Rule remained: $name" } }
  if ($env:ACCEPTANCE_UPLINK) {
    Get-NetIPAddress -InterfaceIndex ([int]$env:ACCEPTANCE_UPLINK) -IPAddress '2001:db8:18::1' -ErrorAction SilentlyContinue | Remove-NetIPAddress -Confirm:$false
    if (Get-NetIPAddress -InterfaceIndex ([int]$env:ACCEPTANCE_UPLINK) -IPAddress '2001:db8:18::1' -ErrorAction SilentlyContinue) { throw 'Controlled IPv6 address remained on the uplink.' }
  }
}
'{}'
