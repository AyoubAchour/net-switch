import { randomBytes, timingSafeEqual } from 'node:crypto';
import { appendFileSync } from 'node:fs';
import { mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import { createServer } from 'node:http';
import { createServer as createTcpServer } from 'node:net';
import path from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import { fileURLToPath } from 'node:url';
import { appKey, AppTracker, connectionLane, mergeRows, OutsideTracker, parseOutsideId } from './lib/apps.mjs';
import { AppInfo } from './lib/appinfo.mjs';
import { Engine } from './lib/engine.mjs';
import { LaneSwitch } from './lib/lane-switch.mjs';
import { createLog } from './lib/logfile.mjs';
import { LineMonitor } from './lib/monitor.mjs';
import {
  allowSimultaneousConnections,
  applyCableAsMain,
  closeTcpConnections,
  describeFailure,
  detectAdapters,
  effectiveMetric,
  findAdapter,
  isElevated,
  laneLabel,
  pickMainAlias,
  readDefaultRoutes,
  readMetrics,
  readMinimizeConnectionsPolicy,
  secondCandidates,
  usableAddresses,
} from './lib/network.mjs';
import { runFile, runPowerShell, SYSTEM32 } from './lib/ps.mjs';
import { Settings } from './lib/settings.mjs';
import { openUndoRecord, undoWindowsChanges } from './lib/windows-undo.mjs';

const mode = process.argv.includes('--dev-proxy') ? 'proxy' : 'tun';
// Test mode keeps its own files and ports, so it can run beside the real one.
const testMode = mode === 'proxy';

const ROOT = path.dirname(fileURLToPath(import.meta.url));

// The value after a command-line flag, or null.
function argument(flag) {
  const index = process.argv.indexOf(flag);
  return index > 0 && process.argv[index + 1] ? path.resolve(process.argv[index + 1]) : null;
}

// Where things are kept. An installed copy is given two folders by launch.ps1:
// - user data (--user-data, %LOCALAPPDATA%\Net Switch): the person's settings,
//   the session file the window and tray read, and the server log;
// - machine data (--machine-data, %ProgramData%\Net Switch, admins only): the
//   record of Windows changes for Undo, and the engine's own files, since
//   those affect the whole PC and feed a program that runs as administrator.
// Run from a source checkout without them, both are data/ (data-test/ in test mode).
const DEFAULT_DIR = path.join(ROOT, testMode ? 'data-test' : 'data');
const USER_DIR = argument('--user-data') ?? DEFAULT_DIR;
const MACHINE_DIR = argument('--machine-data') ?? DEFAULT_DIR;
const UI_DIR = path.join(ROOT, 'ui');
const SERVER_FILE = path.join(USER_DIR, 'server.json');
const SERVER_LOG = path.join(USER_DIR, 'server.log');
const PREFERRED_PORT = testMode ? 47831 : 47821;
// Holding this port is the single-instance lock: Windows releases it the moment
// the process ends, so a crash can never leave a stale lock behind.
const LOCK_PORT = testMode ? 47830 : 47820;
// sing-box reloads the rule-set file 100 ms after it changes.
const RULE_RELOAD_MS = 300;
// Polls in a row that can fail before the speeds are treated as unknown.
const MONITOR_FAILURE_LIMIT = 3;
// Polls in a row the engine may leave unanswered before it counts as hung and
// is restarted. Each one waits up to three seconds, so this is a minute or so.
const ENGINE_HUNG_LIMIT = 20;
// Routing that failed to start, or stopped by itself, is started again after
// these waits, the last one repeating. A run this long resets them.
const RETRY_DELAYS_MS = [5000, 15_000, 30_000, 60_000];
const STEADY_RUN_MS = 120_000;
// The administrator check is tried again this often while it says no: on a
// slow start Windows may not have answered it in time.
const ELEVATION_RECHECK_MS = 30_000;
// A chosen adapter missing from this many good scans in a row counts as gone.
const ADAPTER_GONE_SCANS = 2;
// The adapter list is read this often. When Windows doesn't answer, each try
// that is given up on can leave a stuck request inside Windows, so the wait
// grows with every failure instead of piling them up.
const SCAN_EVERY_MS = 5000;
const POLICY_READ_EVERY_MS = 60_000;
const SCAN_BACKOFF_MAX_MS = 120_000;
const STATIC_FILES = {
  '/': ['index.html', 'text/html; charset=utf-8'],
  '/app.js': ['app.js', 'text/javascript; charset=utf-8'],
  '/styles.css': ['styles.css', 'text/css; charset=utf-8'],
  '/favicon.svg': ['favicon.svg', 'image/svg+xml'],
};

const serverLog = createLog(SERVER_LOG);

// The machine folder holds the undo record and what the engine runs from, so
// only administrators and the system may read or change it. Anyone can create
// folders in %ProgramData%, so the folder may already exist with other owners
// or permissions: it gets a fresh owner and an exact list of who may use it,
// its contents inherit that, and the result is checked. Accounts are named by
// well-known SIDs, which read the same in any Windows language.
const PROTECT_SCRIPT = `
$ErrorActionPreference = 'Stop'
$dir = $env:NETSWITCH_DIR
$admins = New-Object System.Security.Principal.SecurityIdentifier 'S-1-5-32-544'
$system = New-Object System.Security.Principal.SecurityIdentifier 'S-1-5-18'
function Assert-NotLink($item) {
  if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw "$($item.FullName) is a link, which Net Switch won't follow" }
}
Assert-NotLink (Get-Item -LiteralPath $dir -Force)
$acl = New-Object System.Security.AccessControl.DirectorySecurity
$acl.SetOwner($admins)
$acl.SetAccessRuleProtection($true, $false)
foreach ($sid in $admins, $system) {
  $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($sid, 'FullControl', 'ContainerInherit, ObjectInherit', 'None', 'Allow')))
}
Set-Acl -LiteralPath $dir -AclObject $acl
foreach ($item in @(Get-ChildItem -LiteralPath $dir -Recurse -Force)) {
  Assert-NotLink $item
  $child = Get-Acl -LiteralPath $item.FullName
  $child.SetOwner($admins)
  $child.SetAccessRuleProtection($false, $false)
  foreach ($rule in @($child.Access | Where-Object { -not $_.IsInherited })) { [void]$child.RemoveAccessRuleSpecific($rule) }
  Set-Acl -LiteralPath $item.FullName -AclObject $child
}
$check = Get-Acl -LiteralPath $dir
if (-not $check.AreAccessRulesProtected) { throw 'the folder still inherits permissions' }
$allowed = @('S-1-5-32-544', 'S-1-5-18')
$others = @($check.Access | ForEach-Object { $_.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value } | Where-Object { $allowed -notcontains $_ })
if ($others.Count -gt 0) { throw "others still have access: $($others -join ', ')" }
'protected'
`;

async function protectMachineDir(dir) {
  try {
    const output = await runPowerShell(PROTECT_SCRIPT, { timeoutMs: 30_000, args: { DIR: dir } });
    if (!output.includes('protected')) throw new Error('the permission check did not complete');
  } catch (error) {
    // The folder feeds a program that runs as administrator, so Net Switch
    // doesn't start without it locked down. launch.ps1 points to this log.
    const reason = describeFailure(error, 30_000);
    appendFileSync(
      SERVER_LOG,
      `${new Date().toISOString()} Net Switch can't start: ${dir} couldn't be limited to administrators (${reason}). Make sure it is a normal folder, not a link, then start Net Switch again. Don't delete it: it holds the record Undo needs to restore your Windows settings.\n`,
    );
    process.exit(1);
  }
}

await mkdir(USER_DIR, { recursive: true });
await mkdir(MACHINE_DIR, { recursive: true });
// Test mode runs without administrator rights, and would lock itself out.
if (MACHINE_DIR !== USER_DIR && !testMode) await protectMachineDir(MACHINE_DIR);

function log(line) {
  return serverLog.append(line);
}

process.on('unhandledRejection', (error) => {
  log(`unexpected error: ${error?.stack ?? error}`);
});

// Without this the process ends silently and nothing tells why. The line is
// written at once, because the process may not live long enough for a queued
// write. Then routing is stopped the normal way, with a deadline.
process.on('uncaughtException', (error) => {
  try {
    appendFileSync(SERVER_LOG, `${new Date().toISOString()} crashed: ${error?.stack ?? error}\n`);
  } catch {
    // Nowhere left to say it.
  }
  setTimeout(() => process.exit(1), 15_000).unref();
  try {
    shutdown(1).catch(() => process.exit(1));
  } catch {
    // Crashed before the rest of the server existed: nothing to stop yet.
    process.exit(1);
  }
});

const instanceLock = await takeInstanceLock();
if (instanceLock === null) {
  console.log('Net Switch is already running.');
  process.exit(0);
}

const settings = new Settings(USER_DIR, {
  onBackupError: (error) => log(`could not write the settings backup: ${error.message}`),
});
await settings.load();
if (settings.recovery) {
  const { reason, savedAs, usedBackup } = settings.recovery;
  log(`settings were damaged: ${reason}${savedAs ? ` (kept as ${path.basename(savedAs)})` : ''}; ${usedBackup ? 'restored the backup' : 'started from defaults'}`);
}
// How Windows was before Net Switch changed it, so Undo can restore it. Kept
// apart from the settings, which may be reset or shared, because this is the
// only record of the person's own Windows settings.
const windowsUndo = openUndoRecord(MACHINE_DIR, {
  onBackupError: (error) => log(`could not write the Windows undo backup: ${error.message}`),
});
await windowsUndo.load();
if (windowsUndo.recovery) log(`the Windows undo record was damaged: ${windowsUndo.recovery.reason}`);
await moveUndoOutOfSettings();

const engine = new Engine({
  singBoxPath: path.join(ROOT, 'engine', 'sing-box.exe'),
  dataDir: MACHINE_DIR,
  mode,
});
const tracker = new AppTracker();
const outside = new OutsideTracker();
const appInfo = new AppInfo();
const monitor = new LineMonitor({
  // Measuring connections that go around routing needs administrator rights.
  watchOutside: !testMode,
  enginePath: engine.singBoxPath,
});
const token = randomBytes(24).toString('hex');

let adapters = [];
let minimizePolicy = null;
let policyReadAt = 0;
let elevated = false;
let elevationCheckedAt = 0;
// Quit has started: nothing new is started. exiting: routing has stopped and
// the process is about to end, so the polls stop too.
let quitting = false;
let exiting = false;
let monitorFailures = 0;
// Routed connections each line carries, from the last poll.
let lineConnections = { main: 0, second: 0 };
let scanFailures = 0;
let laneQueue = Promise.resolve();
let startQueue = Promise.resolve();
let setupQueue = Promise.resolve();
// Good scans in a row without each chosen adapter.
const adapterMissing = { main: 0, second: 0 };

// Routing should be on unless the person turned it off. While it should be on
// and isn't, it is started again, waiting longer after each failure.
let wantRouting = true;
const retry = { attempts: 0, at: 0 };

// Each lane's selector follows its line: the second connection's apps use the
// cable while it is down, and everything else uses the second connection while
// the cable is down. Their look at the lines doesn't depend on the adapter
// scan, which can fail.
const laneOptions = {
  engine,
  usableAddresses,
  readDefaultRoutes,
  probe: (outbound) => engine.probe(outbound),
  runExclusive: (task) => inLaneQueue(task),
  log: (line) => log(line),
};
const secondLane = new LaneSwitch({
  ...laneOptions,
  lane: 'second',
  getAlias: () => settings.values.secondAlias,
  otherIsUp: () => cableLane.isUp(),
});
const cableLane = new LaneSwitch({
  ...laneOptions,
  lane: 'main',
  getAlias: () => settings.values.mainAlias,
  otherIsUp: () => secondLane.isUp(),
});

engine.on('status', (status) => {
  if (status !== 'on') {
    tracker.reset();
    outside.reset();
    secondLane.reset({ sameLine: true });
    cableLane.reset({ sameLine: true });
    monitorFailures = 0;
    lineConnections = { main: 0, second: 0 };
  }
  // The wait before the next try counts from the failure, not from when the
  // failed start began, and grows with each failure in a row.
  if (status === 'error' && wantRouting && !quitting) {
    retry.at = Date.now() + RETRY_DELAYS_MS[Math.min(retry.attempts, RETRY_DELAYS_MS.length - 1)];
    retry.attempts += 1;
  }
  log(`routing ${status}${engine.error ? `: ${engine.error}` : ''}`);
});

// Connections that go around routing belong to the line whose address they
// use; connections on any other adapter are not on either line.
monitor.on('sample', ({ outside: samples, at }) => {
  if (engine.status !== 'on') return;
  const addressesOf = (alias) => new Set(adapters.find((item) => item.alias === alias)?.ipv4s ?? []);
  const lanes = { main: addressesOf(settings.values.mainAlias), second: addressesOf(settings.values.secondAlias) };
  const laneOf = (local) => (lanes.main.has(local) ? 'main' : lanes.second.has(local) ? 'second' : null);
  // The engine's own outbound sockets also use the line addresses; they are
  // the routed traffic itself and must not be counted twice.
  const enginePid = engine.child?.pid;
  const relevant = samples
    .filter((sample) => sample.pid !== enginePid && laneOf(sample.local))
    .map((sample) => ({
      id: sample.id,
      path: sample.path,
      lane: laneOf(sample.local),
      down: sample.down,
      up: sample.up,
      beforeRouting: Date.parse(sample.created) < engine.startedAt,
    }));
  outside.ingest(relevant, at);
  for (const sample of relevant) appInfo.describe(sample.path ?? '');
});

async function existingServerIsAlive() {
  try {
    const saved = JSON.parse(await readFile(SERVER_FILE, 'utf8'));
    const response = await fetch(`http://127.0.0.1:${saved.port}/api/ping`, {
      headers: { 'X-Token': saved.token },
      signal: AbortSignal.timeout(1500),
    });
    return response.ok;
  } catch {
    return false;
  }
}

// The program holding a local port, from netstat and tasklist (no WMI, which
// can hang). Rows are matched by their numbers, so this reads the same in any
// Windows language. Null when it can't be told.
async function portHolder(port) {
  try {
    const table = await runFile(path.join(SYSTEM32, 'NETSTAT.EXE'), ['-ano', '-p', 'TCP'], { timeoutMs: 10_000 });
    const row = new RegExp(String.raw`^\s*TCP\s+127\.0\.0\.1:${port}\s+0\.0\.0\.0:0\s+\S+\s+(\d+)\s*$`, 'm').exec(table);
    if (!row) return null;
    const pid = Number(row[1]);
    const list = await runFile(path.join(SYSTEM32, 'tasklist.exe'), ['/FI', `PID eq ${pid}`, '/FO', 'CSV', '/NH'], {
      timeoutMs: 10_000,
    });
    const image = /^"([^"]+)"/.exec(list.trim())?.[1];
    return image ? { pid, image: image.toLowerCase() } : null;
  } catch {
    return null;
  }
}

// Returns the held lock, or null when this copy must not run: another Net
// Switch is running or starting, or another program holds the lock port.
async function takeInstanceLock() {
  const lock = createTcpServer((socket) => socket.destroy());
  try {
    await new Promise((resolve, reject) => {
      lock.once('error', reject);
      lock.listen({ port: LOCK_PORT, host: '127.0.0.1', exclusive: true }, resolve);
    });
    lock.unref();
    return lock;
  } catch (error) {
    if (error.code !== 'EADDRINUSE') throw error;
  }
  // Another copy may still be starting: give it time to answer.
  for (let attempt = 0; attempt < 20; attempt += 1) {
    if (await existingServerIsAlive()) return null;
    await delay(500);
  }
  // A copy that is slow to start (Windows can take a while to answer it) holds
  // the lock without answering yet. Two copies would share every file and stop
  // each other's engine, so this copy never runs without the lock: it says
  // which program holds the port and quits.
  const holder = await portHolder(LOCK_PORT);
  await log(
    !holder
      ? `port ${LOCK_PORT} is busy and its program couldn't be identified; Net Switch quits rather than run twice`
      : holder.image === 'node.exe'
        ? `another Net Switch (node.exe, process ${holder.pid}) holds port ${LOCK_PORT} but isn't answering; this copy quits. If Net Switch doesn't open, end that node.exe in Task Manager.`
        : `port ${LOCK_PORT}, which Net Switch uses to make sure it runs once, is held by ${holder.image} (process ${holder.pid}); Net Switch can't start until that program closes`,
  );
  return null;
}

// Older versions kept the Windows undo record in the settings file.
async function moveUndoOutOfSettings() {
  const old = settings.values.setupUndo;
  if (old === undefined) return;
  if (old && typeof old === 'object') {
    await windowsUndo.update((values) => ({
      metrics: { ...(old.metrics ?? {}), ...values.metrics },
      policy: 'value' in values.policy || !('policy' in old) ? values.policy : { value: old.policy },
    }));
  }
  // update() merges, so the key is removed by leaving it undefined, which the
  // saved JSON drops.
  await settings.update({ setupUndo: undefined });
  delete settings.values.setupUndo;
}

// ---------------------------------------------------------------- polling

// The adapter list is for the window and the setup notices (names, Wi-Fi
// network, link details), and to notice when a chosen adapter is renamed or
// replaced. Whether each line is up is decided elsewhere, so a scan Windows
// can't answer never moves anyone to the other line.
async function refreshAdapters() {
  try {
    adapters = await detectAdapters();
    scanFailures = 0;
  } catch (error) {
    scanFailures += 1;
    log(`adapter scan failed: ${describeFailure(error)}; next try in ${Math.round(nextScanDelay() / 1000)} s`);
    return;
  }
  // In the lane queue, like choosing a second connection, so a scan never
  // writes back a choice the person has just replaced.
  await inLaneQueue(followAdapters);
  // The Wi-Fi policy rarely changes, and reading it costs a PowerShell start,
  // so it is read once a minute; Net Switch's own changes re-read it at once.
  if (Date.now() - policyReadAt < POLICY_READ_EVERY_MS) return;
  try {
    minimizePolicy = await readMinimizeConnectionsPolicy();
    policyReadAt = Date.now();
  } catch {
    // Unknown this time; the last reading stands and the next scan tries again.
  }
}

function nextScanDelay() {
  return scanFailures === 0 ? SCAN_EVERY_MS : Math.min(SCAN_EVERY_MS * 2 ** scanFailures, SCAN_BACKOFF_MAX_MS);
}

// Routing binds each line by adapter name, and Windows can rename an adapter
// (a driver update, a USB adapter in another port). Each chosen adapter is
// also known by its id, so a renamed one is followed. A cable adapter that is
// gone for good is replaced by the wired adapter Windows now uses. The
// supervisor then restarts routing so it binds the new name.
async function followAdapters() {
  const { mainAlias, mainGuid, secondAlias, secondGuid } = settings.values;
  const changes = {};
  const notes = [];

  // Adapters that are the same one under a new name, [from, to]: their Undo
  // records follow them. A replaced adapter is a different one, so its
  // record stays with the old name.
  const renamed = [];

  const main = mainAlias ? findAdapter(adapters, { alias: mainAlias, guid: mainGuid }) : null;
  adapterMissing.main = mainAlias && !main ? adapterMissing.main + 1 : 0;
  if (!mainAlias) {
    const picked = adapters.find((item) => item.alias === pickMainAlias(adapters));
    if (picked) Object.assign(changes, { mainAlias: picked.alias, mainGuid: picked.guid || null });
  } else if (main) {
    if (main.alias !== mainAlias) {
      notes.push(`the cable adapter was renamed from ${mainAlias} to ${main.alias}`);
      renamed.push([mainAlias, main.alias]);
    }
    if (main.alias !== mainAlias || (main.guid && main.guid !== mainGuid)) {
      Object.assign(changes, { mainAlias: main.alias, mainGuid: main.guid || null });
    }
  } else if (adapterMissing.main >= ADAPTER_GONE_SCANS) {
    const replacement = adapters.find(
      (item) => item.alias === pickMainAlias(adapters.filter((other) => other.alias !== secondAlias)),
    );
    if (replacement) {
      notes.push(`the cable adapter ${mainAlias} is gone; using ${replacement.alias} instead`);
      Object.assign(changes, { mainAlias: replacement.alias, mainGuid: replacement.guid || null });
    }
  }

  // A second connection that is missing may just be unplugged for now, so it
  // is only followed when renamed, never replaced.
  if (secondAlias) {
    const second = findAdapter(adapters, { alias: secondAlias, guid: secondGuid });
    if (second && second.alias !== secondAlias) {
      notes.push(`the second connection's adapter was renamed from ${secondAlias} to ${second.alias}`);
      renamed.push([secondAlias, second.alias]);
    }
    if (second && (second.alias !== secondAlias || (second.guid && second.guid !== secondGuid))) {
      Object.assign(changes, { secondAlias: second.alias, secondGuid: second.guid || null });
    }
  }

  if (Object.keys(changes).length === 0) return;
  await settings.update(changes);
  for (const note of notes) log(note);
  // Undo records are kept by adapter name. A record already under the new
  // name is the older one, from before Net Switch changed anything, so it
  // wins, unless it is empty (an old version's failed reading).
  const moves = renamed.filter(([from]) => windowsUndo.values.metrics[from]?.length);
  if (moves.length > 0) {
    await windowsUndo.update((values) => {
      const metrics = { ...values.metrics };
      for (const [from, to] of moves) {
        if (!metrics[to]?.length) metrics[to] = metrics[from];
        delete metrics[from];
      }
      return { metrics };
    });
  }
}

// Routing runs with the adapter names it was started with. When the chosen
// names changed since (an adapter was renamed or replaced, also during a
// start), it restarts with the new ones. In the lane queue, so it runs after
// any choice of connection that restarts routing itself.
function rebindIfNeeded() {
  const differs = () =>
    engine.startedWith &&
    (engine.startedWith.mainAlias !== settings.values.mainAlias ||
      engine.startedWith.secondAlias !== settings.values.secondAlias);
  if (!differs()) return null;
  return inLaneQueue(async () => {
    if (!wantRouting || quitting || engine.status !== 'on' || !differs()) return;
    const { mainAlias, secondAlias } = settings.values;
    log(`routing restarts to use ${mainAlias}${secondAlias ? ` and ${secondAlias}` : ''}`);
    await restartEngine();
  });
}

function secondConnectionIsUp() {
  return secondLane.isUp();
}

async function tickLanes() {
  await cableLane.tick();
  await secondLane.tick();
}

async function pollConnections() {
  // The window shows whether each line is connected, also while routing is off.
  cableLane.sample();
  secondLane.sample();
  // A stalled monitor must not leave old speeds on screen.
  if (!monitor.isFresh()) outside.reset();
  if (engine.status !== 'on') return;
  // Each lane's apps use the other line while their own is down (the
  // person's choice), and go back as soon as it returns.
  await tickLanes();
  try {
    const connections = await engine.connections();
    monitorFailures = 0;
    tracker.ingest(connections, Date.now());
    lineConnections = { main: 0, second: 0 };
    for (const connection of connections) lineConnections[connectionLane(connection)] += 1;
    for (const connection of connections) appInfo.describe(connection.metadata?.processPath ?? '');
    appInfo.lookupPending();
  } catch {
    // A slow poll is skipped; several in a row mean the speeds are no longer known.
    monitorFailures += 1;
    if (monitorFailures === MONITOR_FAILURE_LIMIT) {
      tracker.reset();
      log('speed readings stopped: the engine is not answering');
    }
  }
}

// ms is a number, or a function giving the wait before the next run. A run that
// throws is logged (once a minute at most) and the next one still happens:
// one bad reading must not stop the polls for good.
const everyLogged = new Map();
function every(ms, task) {
  const run = async () => {
    try {
      await task();
    } catch (error) {
      if (Date.now() - (everyLogged.get(task.name) ?? 0) > 60_000) {
        everyLogged.set(task.name, Date.now());
        log(`${task.name} failed: ${error?.stack ?? error}`);
      }
    }
    // A quit that fails leaves the server running, so the polls go on until
    // the process is really ending.
    if (!exiting) setTimeout(run, typeof ms === 'function' ? ms() : ms);
  };
  run();
}

// ---------------------------------------------------------------- routing

async function checkElevation() {
  elevationCheckedAt = Date.now();
  // A check Windows didn't answer leaves the last answer standing.
  elevated = await isElevated().catch(() => elevated);
}

// Starts happen one at a time, and a start while routing is already on or
// starting changes nothing. A start the person no longer wants (they turned
// routing off meanwhile, or are quitting) doesn't happen.
function startEngine() {
  const run = async () => {
    if (!wantRouting || quitting) return;
    if (mode === 'tun' && !elevated) {
      engine.setStatus(
        'error',
        'Net Switch needs administrator rights to move apps between connections. Close it and open it again from the Net Switch shortcut.',
      );
      return;
    }
    if (engine.status === 'on' || engine.status === 'starting') {
      await tickLanes();
      return;
    }
    const { mainAlias, secondAlias } = settings.values;
    await engine.start({ mainAlias, secondAlias });
    await tickLanes();
  };
  const result = startQueue.then(run, run);
  startQueue = result.catch(() => {});
  return result;
}

async function restartEngine() {
  await engine.stop();
  await startEngine();
}

// What the person asked for. Turning on also starts the retries afresh.
async function setRouting(on) {
  wantRouting = on;
  if (!on) {
    await engine.stop();
    return;
  }
  retry.attempts = 0;
  retry.at = 0;
  await startEngine();
}

// Once a second: keeps routing on while it should be. Starts that failed and
// engines that stopped by themselves are started again after a growing wait;
// an engine that stops answering is restarted, and one bound to adapter names
// that changed is restarted with the new ones.
async function superviseRouting() {
  if (quitting || !wantRouting) return;
  const status = engine.status;
  if (mode === 'tun' && !elevated) {
    if (Date.now() - elevationCheckedAt >= ELEVATION_RECHECK_MS) await checkElevation();
    if (!elevated) {
      // Says so once; there is nothing to retry until the check says yes.
      if (status !== 'error') await startEngine();
      return;
    }
  }
  if (status === 'on') {
    if (Date.now() - engine.startedAt >= STEADY_RUN_MS) retry.attempts = 0;
    if (monitorFailures >= ENGINE_HUNG_LIMIT) {
      log(`the routing engine hasn't answered for ${monitorFailures} polls; restarting it`);
      monitorFailures = 0;
      await restartEngine();
      return;
    }
    await rebindIfNeeded();
    return;
  }
  if (status !== 'off' && status !== 'error') return;
  if (Date.now() < retry.at) return;
  await startEngine();
}

// ---------------------------------------------------------------- lanes

function inLaneQueue(run) {
  const result = laneQueue.then(run, run);
  laneQueue = result.catch(() => {});
  return result;
}

// One change at a time. The engine's rule file is the routing truth, so it is
// written first; the saved choice follows, and is rolled back if saving fails.
// Reports back only once sing-box has reloaded the rules.
function setAppLane(processPath, lane) {
  return inLaneQueue(async () => {
    if (typeof processPath !== 'string' || processPath === '' || !['main', 'second'].includes(lane)) {
      throw clientError('Choose an app and a connection, then try again.');
    }
    if (lane === 'second' && !settings.values.secondAlias) {
      throw clientError('Set up the second connection first.');
    }
    const previous = settings.values.secondApps;
    const key = appKey(processPath);
    const others = previous.filter((item) => appKey(item) !== key);
    const secondApps = lane === 'second' ? [...others, processPath] : others;
    await engine.setSecondApps(secondApps);
    try {
      await settings.update({ secondApps });
    } catch (error) {
      await engine.setSecondApps(previous).catch(() => {});
      throw error;
    }
    await delay(RULE_RELOAD_MS);
  });
}

// New connections are really being split: the engine's rules combine, routing
// is on and both lines carry their own traffic. While either line is down,
// everything uses the other one.
function combineActive() {
  return engine.combine && engine.status === 'on' && secondLane.home && cableLane.home;
}

// While routing is on with a second connection, the cable's apps use the
// second connection whenever the cable is down.
function cableCarryingApps() {
  return engine.status !== 'on' || !engine.startedWith?.secondAlias || cableLane.target !== 'second';
}

// Combining is one more rule in the same rule file, so it turns on and off
// without restarting routing. Like a line change, it applies to new connections.
function setCombine(on) {
  return inLaneQueue(async () => {
    if (typeof on !== 'boolean') throw clientError('Choose whether to combine both lines, then try again.');
    if (on && !settings.values.secondAlias) throw clientError('Set up the second connection first.');
    const previous = engine.combine;
    await engine.setCombine(on);
    try {
      await settings.update({ combine: on });
    } catch (error) {
      await engine.setCombine(previous).catch((undo) => log(`combining was left ${on ? 'on' : 'off'} after a failed save: ${undo.message}`));
      throw error;
    }
    await delay(RULE_RELOAD_MS);
  });
}

// A live connection can't be moved to another line, only replaced. This closes
// the app's connections that aren't on its chosen line, once, so the app opens
// new ones there; whether it carries on by itself depends on the app.
// It waits behind any pending line change, so it acts on the rules now in force.
function reconnectApp(key) {
  return inLaneQueue(async () => {
    if (typeof key !== 'string' || key === '') throw clientError('Choose an app, then try again.');
    if (engine.status !== 'on') throw clientError('Turn routing on first.');
    const programPath = tracker.snapshot([]).find((row) => row.key === key)?.path ?? outside.get(key)?.path ?? '';
    if (!appInfo.describe(programPath).reconnectable) {
      throw clientError('This one can’t be reconnected, because other programs share its connections.');
    }
    const onSecond = settings.values.secondApps.some((item) => appKey(item) === key);
    if (onSecond && !secondConnectionIsUp()) {
      throw clientError(`The ${settings.values.secondLabel ?? 'second connection'} isn’t connected, so there’s nowhere to move it yet.`);
    }
    // Its connections on the second connection are the fallback working as it
    // should; closing them would only open new ones there again.
    if (!onSecond && !cableCarryingApps()) {
      throw clientError('The cable isn’t connected, so there’s nowhere to move it yet.');
    }
    const chosen = onSecond ? 'second' : 'main';
    // While combining splits traffic, both lines are right for an app on the
    // cable: only its connections that go around routing are out of place.
    // While a line is down, new connections use the other one as usual.
    const bothLines = !onSecond && combineActive();
    let closed = 0;
    let failed = 0;
    // Routed connections: the engine's own count, from the last poll.
    for (const id of bothLines ? [] : tracker.connectionIdsFor(key, onSecond ? 'main' : 'second')) {
      try {
        await engine.closeConnection(id);
        closed += 1;
      } catch {
        failed += 1;
      }
    }
    // Connections around routing, but only those not already on the chosen line.
    const outsideIds = bothLines ? outside.idsOf(key) : outside.idsOffLane(key, chosen);
    const result = await closeTcpConnections(outsideIds.map(parseOutsideId).filter(Boolean));
    closed += result.closed;
    failed += result.failed;
    await log(`reconnect ${key}: closed ${closed}, failed ${failed} (codes ${result.codes.join(',')}), already gone ${result.gone}`);
    return { closed, failed, gone: result.gone };
  });
}

// Waits behind any pending line change. Removing the second connection also
// stops combining, which can't work without it.
function chooseSecondConnection(alias) {
  return inLaneQueue(async () => {
    if (alias === null) {
      const wasCombining = engine.combine;
      await engine.setCombine(false);
      try {
        await settings.update({ secondAlias: null, secondGuid: null, secondLabel: null, secondKind: null, combine: false });
      } catch (error) {
        await engine.setCombine(wasCombining).catch(() => {});
        throw error;
      }
    } else {
      const adapter = adapters.find((item) => item.alias === alias && item.connected);
      // Test mode may reuse the cable as the "second" connection to check routing without a second network.
      const reusesCable = adapter?.alias === settings.values.mainAlias && mode !== 'proxy';
      if (!adapter || reusesCable) {
        throw clientError('That connection isn’t available. Check that it’s connected, then try again.');
      }
      await settings.update({
        secondAlias: alias,
        secondGuid: adapter.guid || null,
        secondLabel: laneLabel(adapter),
        secondKind: adapter.kind,
      });
    }
    if (engine.status !== 'off') await restartEngine();
  });
}

// ---------------------------------------------------------------- Windows changes

// One Windows change or undo at a time, so two windows can't both save a
// "before" record or undo one that is still being made.
function inSetupQueue(run) {
  const result = setupQueue.then(run, run);
  setupQueue = result.catch(() => {});
  return result;
}

// Windows changes always save how things were before they change anything,
// one record per adapter, and only from a reading that worked, so Undo can
// restore exactly.
function makeCableTheDefault() {
  return inSetupQueue(async () => {
    const main = adapters.find((item) => item.alias === settings.values.mainAlias);
    const second = adapters.find((item) => item.alias === settings.values.secondAlias);
    if (!main || !second) throw clientError('Connect both the cable and the second connection, then try again.');
    // An empty record, from versions that saved a failed reading, holds nothing to restore.
    if (!windowsUndo.values.metrics[second.alias]?.length) {
      let before;
      try {
        before = await readMetrics(second.alias);
      } catch (error) {
        log(`could not read ${second.alias}'s settings before changing them: ${error.message}`);
        throw clientError('Windows didn’t say how this connection is set up now, so Net Switch can’t change it safely. Try again in a moment.');
      }
      await windowsUndo.update((values) => ({ metrics: { ...values.metrics, [second.alias]: before } }));
    }
    await applyCableAsMain(main, second, windowsUndo.values.metrics[second.alias]);
    await refreshAdapters();
  });
}

function keepBothConnected() {
  return inSetupQueue(async () => {
    if (!('value' in windowsUndo.values.policy)) {
      let before;
      try {
        before = await readMinimizeConnectionsPolicy();
      } catch (error) {
        log(`could not read the Wi-Fi policy before changing it: ${error.message}`);
        throw clientError('Windows didn’t say how this setting is now, so Net Switch can’t change it safely. Try again in a moment.');
      }
      await windowsUndo.update({ policy: { value: before } });
    }
    await allowSimultaneousConnections();
    minimizePolicy = await readMinimizeConnectionsPolicy().catch(() => minimizePolicy);
  });
}

// Each change is undone and forgotten on its own, so one failure doesn't block the others.
function undoAll() {
  return inSetupQueue(async () => {
    let unreachable;
    try {
      unreachable = await undoWindowsChanges(windowsUndo);
    } catch (error) {
      log(`undo failed: ${error.message}`);
      throw clientError(`Net Switch couldn’t undo the Windows changes: ${error.message}.`);
    }
    minimizePolicy = await readMinimizeConnectionsPolicy().catch(() => minimizePolicy);
    await refreshAdapters();
    if (unreachable.length) {
      throw clientError(`Connect ${unreachable.join(' and ')} again to finish undoing, then press Undo again.`);
    }
  });
}

// ---------------------------------------------------------------- quit

let shuttingDown = null;

// Stops routing and ends the server. Routing has really stopped before this
// returns; if the engine can't be stopped, this throws and the server stays,
// so the window can say so.
// quitting alone keeps routing from starting meanwhile; what the person wants
// is left as it is, so a Turn off that arrives during a failed quit still holds.
function shutdown(code = 0) {
  if (shuttingDown) return shuttingDown;
  quitting = true;
  shuttingDown = (async () => {
    try {
      await engine.stop();
    } catch (error) {
      // Still running: everything goes on as before the quit.
      quitting = false;
      shuttingDown = null;
      log(`quit failed: ${error.message}`);
      throw error;
    }
    exiting = true;
    try {
      monitor.stop();
      // Windows can refuse while another program has the file open; the
      // tray then notices the quit when the server stops answering.
      await rm(SERVER_FILE, { force: true }).catch((error) => log(`could not remove server.json: ${error.message}`));
      await log('quit');
    } finally {
      setTimeout(() => process.exit(code), 100);
    }
  })();
  return shuttingDown;
}

// ---------------------------------------------------------------- state

function laneState(lane) {
  return lane.health.up === false ? lane.health.reason : null;
}

// The last internet test's round trip, while the line counts as up.
function lanePing(lane) {
  return lane.health.up === true ? lane.delay : null;
}

function buildState() {
  const { mainAlias, secondAlias, secondApps, secondLabel, secondKind } = settings.values;
  const main = adapters.find((item) => item.alias === mainAlias) ?? null;
  const second = secondAlias ? (adapters.find((item) => item.alias === secondAlias) ?? null) : null;
  const routingOn = engine.status === 'on';
  const measuring = routingOn && monitorFailures < MONITOR_FAILURE_LIMIT;
  const secondUp = secondConnectionIsUp();
  const wifiPresent = adapters.some((item) => item.kind === 'wifi');
  const undo = windowsUndo.values;

  const apps = mergeRows(tracker.snapshot(secondApps), outside, secondApps).map((app) => {
    const info = appInfo.describe(app.path);
    return {
      key: app.key,
      path: app.path,
      name: info.name,
      hasIcon: info.hasIcon,
      switchable: info.switchable,
      reconnectable: info.reconnectable,
      lane: app.lane,
      rate: app.rate,
      laneDown: app.laneDown,
      sortScore: app.sortScore,
      connections: app.connections,
      outside: app.outside,
    };
  });
  // Real line speeds from Windows, including traffic that goes around routing.
  // No fallback to the engine's own count: that misses exactly this traffic.
  const lineRate = (alias) => monitor.rate(alias);

  return {
    mode,
    elevated,
    features: { reconnect: true, combine: true },
    // From the engine's rules rather than the saved choice, so the window
    // shows what routing really does even if saving the choice failed.
    combine: { on: engine.combine, active: combineActive() },
    routing: {
      status: engine.status,
      // Whether the person wants routing on. While a start is failing it is
      // still true, and the window offers Turn off to stop the retries.
      wanted: wantRouting,
      error: engine.error,
      measuring,
      proxyPort: engine.proxyPort,
      // When routing that should be on is started again by itself.
      retryAt: wantRouting && engine.status === 'error' && (mode !== 'tun' || elevated) ? retry.at : null,
    },
    lanes: {
      main: {
        alias: mainAlias,
        label: 'Cable',
        connected: Boolean(main?.connected),
        // Why the cable counts as down, while it does: 'no address', 'no default route' or 'no internet'.
        problem: laneState(cableLane),
        // Round trip in ms of the last internet test, or null (only tested
        // while routing runs with a second connection).
        ping: lanePing(cableLane),
        connections: lineConnections.main,
        // False while its apps' new connections are going to the second connection.
        carryingApps: cableCarryingApps(),
        rate: lineRate(mainAlias),
        movedBack: cableLane.lastRelease,
      },
      second: secondAlias
        ? {
            alias: secondAlias,
            label: secondLabel ?? laneLabel(second),
            kind: secondKind ?? second?.kind ?? null,
            connected: secondUp,
            problem: laneState(secondLane),
            ping: lanePing(secondLane),
            connections: lineConnections.second,
            ssid: second?.ssid || null,
            // False while its apps' new connections are going to the cable.
            carryingApps: routingOn && secondLane.home,
            rate: lineRate(secondAlias),
            // The last time connections that had moved to the cable were closed so they could return.
            movedBack: secondLane.lastRelease,
          }
        : null,
    },
    candidates: secondCandidates(adapters, mainAlias).map((item) => ({
      alias: item.alias,
      label: laneLabel(item),
      kind: item.kind,
      ssid: item.ssid || null,
    })),
    apps,
    setup: {
      cableNotDefault: Boolean(
        main?.connected &&
          second?.connected &&
          second.alias !== main.alias &&
          effectiveMetric(second) <= effectiveMetric(main),
      ),
      // Policy 3 blocks even connecting Wi-Fi by hand while the cable is plugged in.
      wifiBlocked: minimizePolicy === 3 && wifiPresent,
      keepBothConnected: Boolean(
        secondAlias && (secondKind ?? second?.kind) === 'wifi' && minimizePolicy !== 0 && minimizePolicy !== 3,
      ),
      changed: {
        cableDefault: Object.values(undo.metrics).some((record) => record.length > 0),
        keepBoth: 'value' in undo.policy,
      },
    },
  };
}

// ---------------------------------------------------------------- http

function clientError(message) {
  return Object.assign(new Error(message), { status: 400 });
}

function sameToken(candidate) {
  if (typeof candidate !== 'string' || candidate.length !== token.length) return false;
  return timingSafeEqual(Buffer.from(candidate), Buffer.from(token));
}

function sendJson(response, status, body) {
  response.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' });
  response.end(JSON.stringify(body));
}

async function readJson(request) {
  let size = 0;
  const chunks = [];
  for await (const chunk of request) {
    size += chunk.length;
    if (size > 64 * 1024) throw clientError('Request too large.');
    chunks.push(chunk);
  }
  if (chunks.length === 0) return {};
  try {
    return JSON.parse(Buffer.concat(chunks).toString('utf8'));
  } catch {
    throw clientError('The request could not be read.');
  }
}

const actions = {
  'GET /api/ping': async () => ({ ok: true }),
  'GET /api/state': async () => buildState(),
  'POST /api/routing': async ({ on }) => {
    await setRouting(Boolean(on));
    return buildState();
  },
  'POST /api/app-lane': async ({ path: processPath, lane }) => {
    await setAppLane(processPath, lane);
    return buildState();
  },
  'POST /api/reconnect': async ({ key }) => ({ ...(await reconnectApp(key)), state: buildState() }),
  'POST /api/combine': async ({ on }) => {
    await setCombine(on);
    return buildState();
  },
  'POST /api/second-connection': async ({ alias }) => {
    await chooseSecondConnection(alias ?? null);
    return buildState();
  },
  'POST /api/setup/cable-default': async () => {
    await makeCableTheDefault();
    return buildState();
  },
  'POST /api/setup/keep-both': async () => {
    await keepBothConnected();
    return buildState();
  },
  'POST /api/setup/undo': async () => {
    await undoAll();
    return buildState();
  },
  // Answers once routing has really stopped, so the window never says every
  // app is back on Windows' connection before it is true.
  'POST /api/quit': async () => {
    try {
      await shutdown();
    } catch (error) {
      throw clientError(error.message);
    }
    return { ok: true };
  },
};

let port = PREFERRED_PORT;

const server = createServer(async (request, response) => {
  try {
    const host = request.headers.host ?? '';
    const allowedHosts = [`127.0.0.1:${port}`, `localhost:${port}`];
    if (!allowedHosts.includes(host)) {
      sendJson(response, 403, { error: 'Forbidden' });
      return;
    }
    const origin = request.headers.origin;
    if (request.method !== 'GET' && origin && !allowedHosts.some((item) => origin === `http://${item}`)) {
      sendJson(response, 403, { error: 'Forbidden' });
      return;
    }
    const url = new URL(request.url, `http://${host}`);

    if (url.pathname === '/api/icon') {
      const icon = sameToken(url.searchParams.get('token')) ? appInfo.icon(url.searchParams.get('key')) : null;
      if (!icon) {
        sendJson(response, 404, { error: 'Not found' });
        return;
      }
      response.writeHead(200, { 'Content-Type': 'image/png', 'Cache-Control': 'private, max-age=86400' });
      response.end(icon);
      return;
    }

    if (url.pathname.startsWith('/api/')) {
      if (!sameToken(request.headers['x-token'])) {
        sendJson(response, 401, { error: 'Open Net Switch from its shortcut.' });
        return;
      }
      const action = actions[`${request.method} ${url.pathname}`];
      if (!action) {
        sendJson(response, 404, { error: 'Not found' });
        return;
      }
      const body = request.method === 'POST' ? await readJson(request) : {};
      sendJson(response, 200, await action(body));
      return;
    }

    const file = STATIC_FILES[url.pathname];
    if (!file || request.method !== 'GET') {
      sendJson(response, 404, { error: 'Not found' });
      return;
    }
    const content = await readFile(path.join(UI_DIR, file[0]));
    response.writeHead(200, {
      'Content-Type': file[1],
      'Cache-Control': 'no-cache',
      'Content-Security-Policy':
        "default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; connect-src 'self'; frame-ancestors 'none'",
      'X-Content-Type-Options': 'nosniff',
    });
    response.end(content);
  } catch (error) {
    if (!error.status) log(`request failed: ${error.stack ?? error.message}`);
    sendJson(response, error.status ?? 500, {
      error: error.status ? error.message : 'Something went wrong. Try again.',
    });
  }
});

function listen(onPort) {
  return new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(onPort, '127.0.0.1', () => {
      server.off('error', reject);
      resolve(server.address().port);
    });
  });
}

try {
  port = await listen(PREFERRED_PORT);
} catch {
  port = await listen(0);
}

for (const signal of ['SIGINT', 'SIGTERM', 'SIGHUP', 'SIGBREAK']) {
  process.on(signal, () => shutdown().catch(() => process.exit(1)));
}

await checkElevation();
await refreshAdapters();
await engine.setCombine(Boolean(settings.values.combine));
await engine.setSecondApps(settings.values.secondApps);
await writeFile(SERVER_FILE, JSON.stringify({ port, token, pid: process.pid, mode, startedAt: new Date().toISOString() }));
await log(`started on port ${port} (mode ${mode}, elevated ${elevated})`);
console.log(`Net Switch is running at http://127.0.0.1:${port}/#token=${token}`);

monitor.start();
every(nextScanDelay, refreshAdapters);
every(1000, pollConnections);
every(1000, superviseRouting);
