# Only e2e-tun.mjs on a disposable GitHub-hosted Windows runner may use this.
param([ValidateSet('inspect', 'state', 'dns-state', 'dns-change', 'dns-restore')] [string] $Action)
$ErrorActionPreference = 'Stop'
if ($env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_ENVIRONMENT -ne 'github-hosted') {
  throw 'TUN network tests are restricted to GitHub-hosted runners.'
}
$admin = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $admin.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Administrator rights required.' }
if ($Action -eq 'inspect') {
  $route = Find-NetRoute -RemoteIPAddress '1.1.1.1' | Where-Object { $_.PSObject.Properties.Name -contains 'NextHop' } | Select-Object -First 1
  if (-not $route) { throw 'No route to the public test endpoint.' }
  $adapter = Get-NetAdapter -InterfaceIndex $route.InterfaceIndex
  $key = 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\' + $adapter.InterfaceGuid
  $staticDns = (Get-ItemProperty -LiteralPath $key).NameServer
  $ipv4 = Get-NetIPAddress -InterfaceIndex $adapter.ifIndex -AddressFamily IPv4 |
    Where-Object { $_.AddressState -eq 'Preferred' -and -not $_.SkipAsSource } | Select-Object -First 1
  [pscustomobject]@{ alias = $adapter.Name; index = $adapter.ifIndex; staticDns = $staticDns
    ipv4 = $ipv4.IPAddress
    dns = @((Get-DnsClientServerAddress -InterfaceIndex $adapter.ifIndex -AddressFamily IPv4).ServerAddresses)
  } | ConvertTo-Json -Compress
} elseif ($Action -eq 'state') {
  $adapters = @(Get-NetAdapter -IncludeHidden | Where-Object { $_.Name -eq 'NetSwitch' -or $_.Name -like '*sing-tun*' } | Select-Object Name, ifIndex, Status)
  $routes = @(Get-NetRoute | Where-Object { $_.InterfaceAlias -eq 'NetSwitch' -or $_.InterfaceAlias -like '*sing-tun*' -or $_.DestinationPrefix -like '198.18.0.*' -or $_.DestinationPrefix -like 'fdfe:dcba:9876*' } | Select-Object InterfaceAlias, InterfaceIndex, DestinationPrefix, NextHop)
  $firewall = @(Get-NetFirewallRule | Where-Object { $_.Name -like '*sing-tun*' -or $_.DisplayName -like '*sing-tun*' } | Select-Object Name, DisplayName)
  [pscustomobject]@{ adapters = $adapters; routes = $routes; firewall = $firewall } | ConvertTo-Json -Depth 5 -Compress
} else {
  $index = [int]$env:NETSWITCH_TEST_ADAPTER
  if ($index -le 0) { throw 'Missing test adapter index.' }
  $dnsClient = Get-DnsClientServerAddress -InterfaceIndex $index -AddressFamily IPv4
  if ($Action -eq 'dns-change') {
    $before = @((Get-DnsClientServerAddress -InterfaceIndex $index -AddressFamily IPv4).ServerAddresses)
    $servers = if (($before -join ',') -eq '1.1.1.1,8.8.8.8') { @('8.8.8.8', '1.1.1.1') } else { @('1.1.1.1', '8.8.8.8') }
    $dnsClient | Set-DnsClientServerAddress -ServerAddresses $servers
  } elseif ($Action -eq 'dns-restore') {
    if ($env:NETSWITCH_TEST_STATIC_DNS) {
      $dnsClient | Set-DnsClientServerAddress -ServerAddresses ($env:NETSWITCH_TEST_STATIC_DNS -split '[,;\s]+' | Where-Object { $_ })
    } else {
      $dnsClient | Set-DnsClientServerAddress -ResetServerAddresses
    }
  }
  @((Get-DnsClientServerAddress -InterfaceIndex $index -AddressFamily IPv4).ServerAddresses) | ConvertTo-Json -Compress
}
