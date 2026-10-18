import path from 'node:path';
import { runFile, runPowerShell, runPowerShellJson, SYSTEM32 } from '../ps.mjs';
import { effectiveMetric, parseRouteTable, prepareAdapters, SCAN_TIMEOUT_MS } from '../network.mjs';

const ROUTE = path.join(SYSTEM32, 'route.exe');
const REG = path.join(SYSTEM32, 'reg.exe');
const POLICY_KEY = 'HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\WcmSvc\\GroupPolicy';
const POLICY_VALUE = 'fMinimizeConnections';

export const ADAPTERS_SCRIPT = String.raw`
$ErrorActionPreference = 'SilentlyContinue'
$routes = @(Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0')
$interfaces = @(Get-NetIPInterface -AddressFamily IPv4)
$addresses = @(Get-NetIPAddress -AddressFamily IPv4)
$ssids = @{}
$current = $null
foreach ($line in @(netsh wlan show interfaces)) {
  if ($line -match '^\s*Name\s*:\s*(.+)$') { $current = $Matches[1].Trim() }
  elseif ($current -and $line -match '^\s*SSID\s*:\s*(.*)$') { $ssids[$current] = $Matches[1].Trim() }
}
$list = foreach ($adapter in @(Get-NetAdapter)) {
  $interface = $interfaces | Where-Object { $_.InterfaceIndex -eq $adapter.ifIndex } | Select-Object -First 1
  # Get-NetAdapter can list a stale adapter under another one's interface
  # number. The network stack names each number once; anything else would
  # borrow that adapter's address and routes, and can't be bound to.
  if ($interface -and $interface.InterfaceAlias -ne $adapter.Name) { continue }
  $route = $routes | Where-Object { $_.InterfaceIndex -eq $adapter.ifIndex } | Sort-Object RouteMetric | Select-Object -First 1
  $own = @($addresses | Where-Object { $_.InterfaceIndex -eq $adapter.ifIndex -and $_.IPAddress -notlike '169.254.*' })
  $address = $own | Select-Object -First 1
  [pscustomobject]@{
    alias = $adapter.Name
    guid = [string]$adapter.InterfaceGuid
    mac = [string]$adapter.MacAddress
    index = [int]$adapter.ifIndex
    description = [string]$adapter.InterfaceDescription
    status = [string]$adapter.Status
    mediaType = [string]$adapter.PhysicalMediaType
    linkSpeed = [string]$adapter.LinkSpeed
    virtual = [bool]$adapter.Virtual
    gateway = if ($route) { [string]$route.NextHop } else { $null }
    routeMetric = if ($route) { [int]$route.RouteMetric } else { $null }
    ipv4 = if ($address) { [string]$address.IPAddress } else { $null }
    ipv4s = @($own | ForEach-Object { [string]$_.IPAddress })
    metric = if ($interface) { [int]$interface.InterfaceMetric } else { $null }
    automaticMetric = if ($interface) { [string]$interface.AutomaticMetric -eq 'Enabled' } else { $null }
    ssid = $ssids[$adapter.Name]
  }
}
ConvertTo-Json -InputObject @($list) -Compress -Depth 3
`;

export async function detectAdapters() {
  const list = (await runPowerShellJson(ADAPTERS_SCRIPT, { timeoutMs: SCAN_TIMEOUT_MS })) ?? [];
  return prepareAdapters(list);
}

// Throws when the output is not a route table, so "couldn't read it" is never
// mistaken for "there is no default route".
export async function readDefaultRoutes() {
  const { routes, rows } = parseRouteTable(await runFile(ROUTE, ['print', '-4'], { timeoutMs: 5000 }));
  if (rows === 0) throw new Error('route.exe printed no routes.');
  return routes;
}

export async function isElevated() {
  const output = await runPowerShell(
    '([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)',
  );
  return output.trim() === 'True';
}

// The current priority settings of one adapter, per address family. A family
// the adapter doesn't have (IPv6 turned off) is left out; any other failure
// fails the whole reading, so a half reading is never saved for Undo.
export async function readMetrics(alias) {
  const list = await runPowerShellJson(
    `
$list = foreach ($family in 'IPv4', 'IPv6') {
  try {
    $i = Get-NetIPInterface -InterfaceAlias $env:NETSWITCH_ALIAS -AddressFamily $family -ErrorAction Stop
  } catch {
    if ($_.CategoryInfo.Category -eq 'ObjectNotFound') { continue }
    throw
  }
  [pscustomobject]@{ family = $family; automatic = ([string]$i.AutomaticMetric -eq 'Enabled'); metric = $i.InterfaceMetric }
}
ConvertTo-Json -InputObject @($list) -Compress
`,
    { args: { ALIAS: alias } },
  );
  if (!Array.isArray(list) || list.length === 0 || list.some((item) => !Number.isFinite(item?.metric))) {
    throw new Error(`Windows did not return valid interface metrics for "${alias}"; the original settings cannot be saved for Undo.`);
  }
  return list;
}

async function writeMetric(alias, { family, automatic, metric }) {
  if (family !== 'IPv4' && family !== 'IPv6') throw new Error(`Unknown address family ${family}`);
  const script = automatic
    ? `Set-NetIPInterface -InterfaceAlias $env:NETSWITCH_ALIAS -AddressFamily ${family} -AutomaticMetric Enabled -ErrorAction Stop`
    : `Set-NetIPInterface -InterfaceAlias $env:NETSWITCH_ALIAS -AddressFamily ${family} -AutomaticMetric Disabled -InterfaceMetric $env:NETSWITCH_METRIC -ErrorAction Stop`;
  await runPowerShell(script, { args: { ALIAS: alias, METRIC: Math.trunc(Number(metric)) } });
}

// When Net Switch is off, Windows uses the lowest metric. A fast Wi-Fi link can
// outrank a 100 Mbps cable, so each other line gets a clearly higher one than
// the main line. before is the saved readMetrics() of that other adapter: only
// the address families in it are changed, so everything changed can be undone.
export async function applyCableAsMain(mainAdapter, secondAdapter, before) {
  const target = Math.max(100, effectiveMetric(mainAdapter) + 50);
  for (const item of before) {
    await writeMetric(secondAdapter.alias, { family: item.family, automatic: false, metric: target });
  }
}

export async function restoreMetrics(alias, metrics) {
  for (const item of metrics) await writeMetric(alias, item);
}

// Ends IPv4 TCP connections that go around routing, the same way an admin tool
// would (SetTcpEntry with DELETE_TCB). Each one is first checked to still be
// the same connection (same owner and start time, still established), so a
// reused address and port is left alone. A tiny race remains: Windows offers
// no way to close "this exact connection" atomically.
// Connections arrive as JSON in an environment variable, never in the script text.
const CLOSE_SCRIPT = String.raw`
Add-Type -TypeDefinition @'
using System;
using System.Net;
using System.Runtime.InteropServices;

public static class NetSwitchTcpClose {
  [StructLayout(LayoutKind.Sequential)]
  struct MibTcpRow { public uint State; public uint LocalAddr; public uint LocalPort; public uint RemoteAddr; public uint RemotePort; }

  [DllImport("iphlpapi.dll")]
  static extern uint SetTcpEntry(ref MibTcpRow row);

  static uint Port(int port) { return (uint)(((port & 0xFF) << 8) | ((port >> 8) & 0xFF)); }

  public static uint Close(string local, int localPort, string remote, int remotePort) {
    MibTcpRow row = new MibTcpRow();
    row.State = 12;
    row.LocalAddr = BitConverter.ToUInt32(IPAddress.Parse(local).GetAddressBytes(), 0);
    row.LocalPort = Port(localPort);
    row.RemoteAddr = BitConverter.ToUInt32(IPAddress.Parse(remote).GetAddressBytes(), 0);
    row.RemotePort = Port(remotePort);
    return SetTcpEntry(ref row);
  }
}
'@
$closed = 0
$failed = 0
$gone = 0
$codes = @()
foreach ($c in @($env:NETSWITCH_CONNECTIONS | ConvertFrom-Json)) {
  $live = Get-NetTCPConnection -LocalAddress $c.local -LocalPort $c.lport -RemoteAddress $c.remote -RemotePort $c.rport -State Established -ErrorAction SilentlyContinue |
    Where-Object { $_.OwningProcess -eq $c.pid -and $_.CreationTime.ToUniversalTime().ToString('o') -eq $c.created }
  if (-not $live) { $gone++; continue }
  $code = [NetSwitchTcpClose]::Close($c.local, [int]$c.lport, $c.remote, [int]$c.rport)
  if ($code -eq 0) { $closed++ } else { $failed++; $codes += $code }
}
[pscustomobject]@{ closed = $closed; failed = $failed; gone = $gone; codes = @($codes) } | ConvertTo-Json -Compress
`;

// Returns how many were closed, how many could not be, and how many had
// already ended (or turned out to be a different connection) by then.
export async function closeTcpConnections(connections) {
  if (connections.length === 0) return { closed: 0, failed: 0, gone: 0, codes: [] };
  const result = await runPowerShellJson(CLOSE_SCRIPT, {
    timeoutMs: 30_000,
    args: { CONNECTIONS: JSON.stringify(connections) },
  });
  return {
    closed: result?.closed ?? 0,
    failed: result?.failed ?? connections.length,
    gone: result?.gone ?? 0,
    codes: result?.codes ?? [],
  };
}

// Read through .NET rather than reg.exe: reg.exe says a value is missing only
// in the words of the Windows display language, which can't be matched
// reliably. Here a missing key or value is simply null.
const POLICY_SUBKEY = POLICY_KEY.replace(/^HKLM\\/, '');
// Any error stops the script with a non-zero exit, so a failed read (access
// denied, a damaged key) is never mistaken for "not set".
const POLICY_READ_SCRIPT = `
$ErrorActionPreference = 'Stop'
$key = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($env:NETSWITCH_KEY)
if ($null -eq $key) { 'absent'; exit 0 }
$value = $key.GetValue($env:NETSWITCH_VALUE, $null)
if ($null -eq $value) { 'absent' } else { [string][int]$value }
`;

// The policy's value, or null when it isn't set. Throws when it can't be read,
// so a failed reading is never saved for Undo as "not set".
export async function readMinimizeConnectionsPolicy() {
  const output = (
    await runPowerShell(POLICY_READ_SCRIPT, { timeoutMs: 10_000, args: { KEY: POLICY_SUBKEY, VALUE: POLICY_VALUE } })
  ).trim();
  if (output === 'absent') return null;
  const value = Number.parseInt(output, 10);
  if (!Number.isInteger(value)) {
    throw new Error(`Windows did not return a number for ${POLICY_VALUE}; the original policy cannot be saved for Undo.`);
  }
  return value;
}

// Policy 0 lets Windows keep Wi-Fi connected while the cable is plugged in.
// reg.exe only touches this one value and leaves the rest of the key alone.
// The caller saves readMinimizeConnectionsPolicy() first, for undo.
export async function allowSimultaneousConnections() {
  await runFile(REG, ['add', POLICY_KEY, '/v', POLICY_VALUE, '/t', 'REG_DWORD', '/d', '0', '/f']);
}

export async function restoreMinimizeConnectionsPolicy(value) {
  if (value === null || value === undefined) {
    // Removes only this value; a key or value that is already gone is fine.
    // Any other error stops the script, so the undo record keeps this entry.
    await runPowerShell(
      `$ErrorActionPreference = 'Stop'
$key = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($env:NETSWITCH_KEY, $true)
if ($null -ne $key) { $key.DeleteValue($env:NETSWITCH_VALUE, $false) }`,
      { timeoutMs: 10_000, args: { KEY: POLICY_SUBKEY, VALUE: POLICY_VALUE } },
    );
  } else {
    const number = Math.trunc(Number(value));
    await runFile(REG, ['add', POLICY_KEY, '/v', POLICY_VALUE, '/t', 'REG_DWORD', '/d', String(number), '/f']);
  }
}
