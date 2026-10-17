import { spawn as spawnProcess } from 'node:child_process';
import { EventEmitter } from 'node:events';
import { existsSync } from 'node:fs';
import path from 'node:path';
import { createInterface } from 'node:readline';
import { spawnPowerShell } from './ps.mjs';

// Two long-running helpers, reporting once a second. They are separate so that
// one stuck waiting on Windows cannot blind the other.
// - meters: bytes per network adapter, so the line meters show the real load.
// - outside (while routing is on): TCP connections that go around the routing
//   engine, for example a download that was already running when routing
//   started. Their byte counts come from Windows' per-connection statistics
//   (Get/SetPerTcpConnectionEStats), which needs administrator rights.
// Both are netswitch-helper.exe, a small native program (helper\), run in one
// mode each. Without it, as in a source checkout that hasn't built it, two
// PowerShell scripts print exactly the same lines instead. They use about a
// hundred megabytes each where the native helper uses a few.

// The installed copy has the helper in helper\; a source checkout has it in
// helper\bin\ once `npm run build:helper` has built it. Null when neither is there.
export function findHelper(root, exists = existsSync) {
  const places = [path.join(root, 'helper', 'netswitch-helper.exe'), path.join(root, 'helper', 'bin', 'netswitch-helper.exe')];
  return places.find((file) => exists(file)) ?? null;
}

// The helper's standard input is a pipe that is never written to: the helper
// also ends when it closes, which Windows does as soon as this server is gone.
function spawnHelperFile(file, args) {
  const child = spawnProcess(file, args, { windowsHide: true, stdio: ['pipe', 'pipe', 'pipe'] });
  // Nothing is written, but an error on that pipe must not crash the server.
  child.stdin?.on('error', () => {});
  return child;
}

// Bytes per network adapter, read from Windows' interface table through .NET
// (the native helper reads the same table the same way).
// Not Get-NetAdapterStatistics: that goes through WMI, which can hang for
// minutes, and it doesn't list the USB Wi-Fi stick at all. An adapter whose
// counters can't be read is left out of that second.
export const ADAPTER_STATS = String.raw`
  $adapters = @(foreach ($n in [System.Net.NetworkInformation.NetworkInterface]::GetAllNetworkInterfaces()) {
    $s = $null
    try { $s = $n.GetIPStatistics() } catch {}
    if ($s) { [pscustomobject]@{ alias = $n.Name; rx = [double]$s.BytesReceived; tx = [double]$s.BytesSent } }
  })
`;

const METER_SCRIPT = String.raw`
$ErrorActionPreference = 'SilentlyContinue'
# Windows doesn't end child processes with their parent: stop once the server is gone.
$parent = [int]$env:NETSWITCH_PARENT
while ($true) {
  if (-not (Get-Process -Id $parent -ErrorAction SilentlyContinue)) { exit }
${ADAPTER_STATS}
  $line = [pscustomobject]@{ adapters = @($adapters) } | ConvertTo-Json -Compress -Depth 4
  [Console]::Out.WriteLine($line)
  Start-Sleep -Milliseconds 1000
}
`;

const OUTSIDE_SCRIPT = String.raw`
$ErrorActionPreference = 'SilentlyContinue'
$estats = $false
try {
  Add-Type -TypeDefinition @'
using System;
using System.Net;
using System.Runtime.InteropServices;

public static class NetSwitchTcpStats {
  [StructLayout(LayoutKind.Sequential)]
  struct MibTcpRow { public uint State; public uint LocalAddr; public uint LocalPort; public uint RemoteAddr; public uint RemotePort; }

  [StructLayout(LayoutKind.Sequential)]
  struct DataRw { public byte EnableCollection; }

  [StructLayout(LayoutKind.Sequential)]
  struct DataRod {
    public ulong DataBytesOut; public ulong DataSegsOut; public ulong DataBytesIn; public ulong DataSegsIn;
    public ulong SegsOut; public ulong SegsIn; public uint SoftErrors; public uint SoftErrorReason;
    public uint SndUna; public uint SndNxt; public uint SndMax; public ulong ThruBytesAcked;
    public uint RcvNxt; public ulong ThruBytesReceived;
  }

  const int TcpConnectionEstatsData = 1;

  [DllImport("iphlpapi.dll")]
  static extern uint SetPerTcpConnectionEStats(ref MibTcpRow row, int type, ref DataRw rw, uint rwVersion, uint rwSize, uint offset);

  [DllImport("iphlpapi.dll")]
  static extern uint GetPerTcpConnectionEStats(ref MibTcpRow row, int type, ref DataRw rw, uint rwVersion, uint rwSize, IntPtr ros, uint rosVersion, uint rosSize, ref DataRod rod, uint rodVersion, uint rodSize);

  // Addresses and ports go in network byte order.
  static uint Port(int port) { return (uint)(((port & 0xFF) << 8) | ((port >> 8) & 0xFF)); }

  static MibTcpRow Row(string local, int localPort, string remote, int remotePort) {
    MibTcpRow row = new MibTcpRow();
    row.State = 5;
    row.LocalAddr = BitConverter.ToUInt32(IPAddress.Parse(local).GetAddressBytes(), 0);
    row.LocalPort = Port(localPort);
    row.RemoteAddr = BitConverter.ToUInt32(IPAddress.Parse(remote).GetAddressBytes(), 0);
    row.RemotePort = Port(remotePort);
    return row;
  }

  public static uint Enable(string local, int localPort, string remote, int remotePort) {
    MibTcpRow row = Row(local, localPort, remote, remotePort);
    DataRw rw = new DataRw();
    rw.EnableCollection = 1;
    return SetPerTcpConnectionEStats(ref row, TcpConnectionEstatsData, ref rw, 0, (uint)Marshal.SizeOf(typeof(DataRw)), 0);
  }

  // Windows documents the counters as meaningless unless EnableCollection
  // comes back set, so anything else counts as "not measured".
  public static ulong[] Read(string local, int localPort, string remote, int remotePort) {
    MibTcpRow row = Row(local, localPort, remote, remotePort);
    DataRw rw = new DataRw();
    DataRod rod = new DataRod();
    uint result = GetPerTcpConnectionEStats(ref row, TcpConnectionEstatsData, ref rw, 0, (uint)Marshal.SizeOf(typeof(DataRw)), IntPtr.Zero, 0, 0, ref rod, 0, (uint)Marshal.SizeOf(typeof(DataRod)));
    if (result != 0 || rw.EnableCollection != 1) return null;
    return new ulong[] { rod.DataBytesIn, rod.DataBytesOut };
  }
}
'@
  $estats = $true
} catch {}

$watchOutside = $env:NETSWITCH_OUTSIDE -eq '1'
$engine = $env:NETSWITCH_ENGINE
# Windows doesn't end child processes with their parent: stop once the server is gone.
$parent = [int]$env:NETSWITCH_PARENT
$skipLocal = @('127.0.0.1', '0.0.0.0', '198.18.0.1')
$privateRemote = '^(10\.|127\.|169\.254\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.|22[4-9]\.|23[0-9]\.|255\.)'
$tracked = @{}
$tick = 0
while ($true) {
  if (-not (Get-Process -Id $parent -ErrorAction SilentlyContinue)) { exit }
  $outside = @()
  if ($watchOutside) {
    if ($tick % 5 -eq 0) {
      $paths = @{}
      $seen = @{}
      foreach ($c in @(Get-NetTCPConnection -State Established)) {
        if ($c.LocalAddress -notmatch '^\d+\.\d+\.\d+\.\d+$') { continue }
        if ($skipLocal -contains $c.LocalAddress -or $c.RemoteAddress -match $privateRemote) { continue }
        $owner = [int]$c.OwningProcess
        if (-not $paths.ContainsKey($owner)) { $paths[$owner] = [string](Get-Process -Id $owner).Path }
        if ($engine -and $paths[$owner] -eq $engine) { continue }
        $created = $c.CreationTime.ToUniversalTime().ToString('o')
        # Owner and start time too, so a reused address and port is never mistaken for the old connection.
        $key = "$($c.LocalAddress):$($c.LocalPort)>$($c.RemoteAddress):$($c.RemotePort)|$owner|$created"
        $seen[$key] = $true
        if (-not $tracked.ContainsKey($key)) {
          $measured = $false
          if ($estats) { $measured = [NetSwitchTcpStats]::Enable($c.LocalAddress, [int]$c.LocalPort, $c.RemoteAddress, [int]$c.RemotePort) -eq 0 }
          $tracked[$key] = [pscustomobject]@{
            id = $key; pid = $owner; path = $paths[$owner]; local = $c.LocalAddress; lport = [int]$c.LocalPort
            remote = $c.RemoteAddress; rport = [int]$c.RemotePort; created = $created; measured = $measured
          }
        }
      }
      foreach ($key in @($tracked.Keys)) { if (-not $seen.ContainsKey($key)) { $tracked.Remove($key) } }
    }
    $outside = foreach ($t in $tracked.Values) {
      $bytes = $null
      if ($t.measured) { $bytes = [NetSwitchTcpStats]::Read($t.local, $t.lport, $t.remote, $t.rport) }
      [pscustomobject]@{
        id = $t.id; pid = $t.pid; path = $t.path; local = $t.local; created = $t.created
        down = if ($bytes) { [double]$bytes[0] } else { $null }
        up = if ($bytes) { [double]$bytes[1] } else { $null }
      }
    }
  }
  $line = [pscustomobject]@{ estats = $estats; outside = @($outside) } | ConvertTo-Json -Compress -Depth 4
  [Console]::Out.WriteLine($line)
  $tick++
  Start-Sleep -Milliseconds 1000
}
`;

const STALE_MS = 5000;
const RESTART_MIN_MS = 3000;
const RESTART_MAX_MS = 60_000;
// A helper that has said nothing for this long is stuck, for example waiting
// for Windows: it is ended, and started again like one that died.
const SILENT_MS = 30_000;

export class LineMonitor extends EventEmitter {
  // helperPath is netswitch-helper.exe, or null to use the PowerShell scripts.
  // Both ways of starting a helper and the three timings can be replaced, to
  // test the restarts quickly.
  constructor({
    watchOutside,
    enginePath,
    helperPath = null,
    spawn = spawnPowerShell,
    spawnHelper = spawnHelperFile,
    silentMs = SILENT_MS,
    watchdogMs = 5000,
    restartMinMs = RESTART_MIN_MS,
    log = () => {},
  }) {
    super();
    this.watchOutside = watchOutside;
    this.enginePath = enginePath;
    this.helperPath = helperPath;
    this.spawn = spawn;
    this.spawnHelper = spawnHelper;
    this.silentMs = silentMs;
    this.watchdogMs = watchdogMs;
    this.restartMinMs = restartMinMs;
    this.log = log;
    this.helpers = new Map();
    this.stopped = false;
    this.adapters = new Map();
    this.lastMeterAt = 0;
    this.lastSampleAt = 0;
    this.estats = false;
  }

  start() {
    this.stopped = false;
    const starts = this.helperStarts();
    this.launch('meters', starts.meters);
    if (this.watchOutside) this.launch('outside', starts.outside);
  }

  // How each helper is started: the native helper in that mode, or the
  // PowerShell script that prints the same lines. Each follows this server's
  // process and ends with it.
  helperStarts() {
    const parent = process.pid;
    if (this.helperPath) {
      const engine = this.enginePath ? ['--engine', this.enginePath] : [];
      return {
        meters: () => this.spawnHelper(this.helperPath, ['meters', '--parent', String(parent)]),
        outside: () => this.spawnHelper(this.helperPath, ['outside', '--parent', String(parent), ...engine]),
      };
    }
    return {
      meters: () => this.spawn(METER_SCRIPT, { args: { PARENT: parent } }),
      outside: () => this.spawn(OUTSIDE_SCRIPT, { args: { OUTSIDE: '1', ENGINE: this.enginePath, PARENT: parent } }),
    };
  }

  launch(name, start) {
    const helper = this.helpers.get(name) ?? { child: null, restartDelay: this.restartMinMs, watchdog: null, lastLineAt: 0 };
    this.helpers.set(name, helper);
    let child;
    try {
      child = start();
    } catch (error) {
      this.log(`${name} helper could not start: ${error.message}`);
      this.scheduleRestart(name, start);
      return;
    }
    helper.child = child;
    helper.lastLineAt = Date.now();
    createInterface({ input: child.stdout }).on('line', (line) => {
      if (this.stopped || helper.child !== child) return;
      if (this.handleLine(line)) {
        helper.lastLineAt = Date.now();
        helper.restartDelay = this.restartMinMs;
      }
    });
    createInterface({ input: child.stderr }).on('line', (line) => this.log(`${name} helper: ${line.slice(0, 500)}`));
    // A helper that could not even start (it never got a process id) reports an
    // error and never exits, so that error ends it. An error from a running
    // one, for example a kill that failed, does not: it is still there, and its
    // exit will end it. Whichever ending comes first counts, once.
    let ended = false;
    const end = () => {
      if (ended) return;
      ended = true;
      if (helper.child === child) helper.child = null;
      clearInterval(helper.watchdog);
      this.emit('helperExit', name);
      this.scheduleRestart(name, start);
    };
    child.on('error', (error) => {
      this.log(`${name} helper: ${error.message}`);
      if (child.pid === undefined) end();
    });
    child.on('exit', end);
    child.on('close', end);
    helper.watchdog = setInterval(() => {
      if (Date.now() - helper.lastLineAt > this.silentMs) {
        this.log(`${name} helper stopped reporting; restarting it`);
        child.kill();
      }
    }, this.watchdogMs);
    helper.watchdog.unref();
  }

  // Restart a helper that died, waiting longer each time it keeps failing.
  scheduleRestart(name, start) {
    if (this.stopped) return;
    const helper = this.helpers.get(name);
    const wait = helper.restartDelay;
    this.log(`${name} helper stopped; next try in ${Math.round(wait / 1000)} s`);
    helper.restartDelay = Math.min(helper.restartDelay * 2, RESTART_MAX_MS);
    setTimeout(() => !this.stopped && !helper.child && this.launch(name, start), wait).unref();
  }

  stop() {
    this.stopped = true;
    for (const helper of this.helpers.values()) {
      clearInterval(helper.watchdog);
      helper.child?.kill();
      helper.child = null;
    }
  }

  // Returns whether the line was a reading.
  handleLine(line) {
    let sample;
    try {
      sample = JSON.parse(line);
    } catch {
      return false;
    }
    const now = Date.now();
    if (Array.isArray(sample.adapters)) {
      const present = new Set();
      for (const adapter of sample.adapters) {
        if (!adapter?.alias) continue;
        present.add(adapter.alias);
        const before = this.adapters.get(adapter.alias);
        const seconds = before ? Math.max((now - before.at) / 1000, 0.2) : null;
        this.adapters.set(adapter.alias, {
          rx: adapter.rx,
          tx: adapter.tx,
          at: now,
          // Counters restart when an adapter reconnects; never report a negative speed.
          rate: seconds
            ? { down: Math.max(0, adapter.rx - before.rx) / seconds, up: Math.max(0, adapter.tx - before.tx) / seconds }
            : null,
        });
      }
      // An unplugged adapter must not keep showing its last speed.
      for (const alias of this.adapters.keys()) if (!present.has(alias)) this.adapters.delete(alias);
      this.lastMeterAt = now;
    }
    if (Array.isArray(sample.outside)) {
      this.estats = Boolean(sample.estats);
      this.lastSampleAt = now;
      this.emit('sample', { outside: sample.outside, at: now });
    }
    return true;
  }

  // The connections that go around routing are current. (Without that helper,
  // as in test mode, the meters tell whether the monitor is alive.)
  isFresh() {
    const last = this.watchOutside ? this.lastSampleAt : this.lastMeterAt;
    return Date.now() - last <= STALE_MS;
  }

  // Real speed of one adapter, or null when there is no recent reading for it.
  rate(alias) {
    const adapter = alias ? this.adapters.get(alias) : null;
    if (!adapter || Date.now() - adapter.at > STALE_MS) return null;
    return adapter.rate;
  }

  // Byte totals of one adapter since Windows started counting, { rx, tx }, or
  // null when there is no recent reading for it. Data caps count from these.
  counters(alias) {
    const adapter = alias ? this.adapters.get(alias) : null;
    if (!adapter || Date.now() - adapter.at > STALE_MS) return null;
    return { rx: adapter.rx, tx: adapter.tx };
  }
}
