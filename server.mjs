import { randomBytes, timingSafeEqual } from 'node:crypto';
import { appendFileSync } from 'node:fs';
import { mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import { createServer } from 'node:http';
import { createServer as createTcpServer } from 'node:net';
import path from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import { fileURLToPath } from 'node:url';
import { appKey, appPins, AppTracker, connectionLine, mergeRows, OutsideTracker, parseOutsideId } from './lib/apps.mjs';
import { AppInfo } from './lib/appinfo.mjs';
import { canAutostart, disableAutostart, enableAutostart, readAutostart } from './lib/autostart.mjs';
import { Engine, probeUrls } from './lib/engine.mjs';
import { InstalledApps } from './lib/installed-apps.mjs';
import { LaneSwitch } from './lib/lane-switch.mjs';
import {
  LEGACY_KEYS,
  lineLabel,
  MAX_LABEL_LENGTH,
  migrateSettings,
  newLine,
  normalizeLines,
  pickFirstAdapter,
  SHARE_STEP,
  sharesFromWeights,
  sharingLines,
  validCap,
  withoutLegacyKeys,
} from './lib/lines.mjs';
import { createLog } from './lib/logfile.mjs';
import { findHelper, LineMonitor } from './lib/monitor.mjs';
import {
  allowSimultaneousConnections,
  applyCableAsMain,
  closeTcpConnections,
  describeFailure,
  detectAdapters,
  effectiveMetric,
  findAdapter,
  hasGlobalIPv6,
  isElevated,
  readDefaultRoutes,
  readMetrics,
  readMinimizeConnectionsPolicy,
  usableAddresses,
} from './lib/network.mjs';
import { runFile, runPowerShell, SYSTEM32 } from './lib/ps.mjs';
import { Settings, writeFileAtomic } from './lib/settings.mjs';
import { UpdateChecker } from './lib/updates.mjs';
import { Usage } from './lib/usage.mjs';
import { openUndoRecord, undoWindowsChanges } from './lib/windows-undo.mjs';

const mode = process.argv.includes('--dev-proxy') ? 'proxy' : 'tun';
// Test mode keeps its own files and ports, so it can run beside the real one.
const testMode = mode === 'proxy';

const ROOT = path.dirname(fileURLToPath(import.meta.url));
// The installer ships package.json, so this is the version the person runs.
const APP_VERSION = JSON.parse(await readFile(path.join(ROOT, 'package.json'), 'utf8')).version;

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
// What each line used this period, and how fast each line can go.
const USAGE_FILE = path.join(USER_DIR, 'usage.json');
const USAGE_SAVE_EVERY_MS = 60_000;
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
// More lines than this would make combining's shares too thin to matter.
const MAX_LINES = 8;
// Auto combining rewrites the shares at most this often, and only when one
// moves at least this much, so the rule files don't churn with every reading.
const AUTO_SHARE_EVERY_MS = 60_000;
const AUTO_SHARE_MIN_MOVE = 2 * SHARE_STEP;
// Line events (down, back, out of data) the window and tray can show.
const EVENTS_KEPT = 20;
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
await migrateLines();

// Looks for a newer release, unless the person turned that off. Test mode
// never checks: it runs beside a real copy, which already does.
const updates = new UpdateChecker({
  currentVersion: APP_VERSION,
  enabled: () => !testMode && settings.values.checkForUpdates,
  log: (line) => log(line),
});

// The newer release to offer, unless the person said "not now" to that one.
function updateOffer() {
  const offer = updates.offer;
  return offer && offer.version !== settings.values.skippedUpdate ? offer : null;
}

// Test mode may use the engine of another checkout (a git worktree has none).
// Never the real one: it runs the engine as administrator.
const ENGINE_DIR = (testMode && argument('--engine-dir')) || path.join(ROOT, 'engine');
const engine = new Engine({
  singBoxPath: path.join(ENGINE_DIR, 'sing-box.exe'),
  dataDir: MACHINE_DIR,
  mode,
});
const tracker = new AppTracker();
const outside = new OutsideTracker();
const appInfo = new AppInfo();
const installedApps = new InstalledApps({ appInfo });
const monitor = new LineMonitor({
  // Measuring connections that go around routing needs administrator rights.
  watchOutside: !testMode,
  enginePath: engine.singBoxPath,
  helperPath: findHelper(ROOT),
});
log(
  monitor.helperPath
    ? `line readings come from ${path.relative(ROOT, monitor.helperPath)}`
    : 'line readings come from PowerShell: the native helper is not built (npm run build:helper)',
);
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
// Routed connections each line carries, from the last poll: { [lineId]: n }.
let lineConnections = {};
let scanFailures = 0;
let laneQueue = Promise.resolve();
let startQueue = Promise.resolve();
let setupQueue = Promise.resolve();
// Good scans in a row without each line's adapter, by line id.
const adapterMissing = new Map();
// Line events for the window and the tray's notifications, newest last.
const events = [];
// Lines out of data for this period, as of the last poll.
let exhaustedIds = new Set();
// When Auto combining last rewrote the shares.
let sharesWrittenAt = 0;
// Since when whether to route IPv6 has differed from what routing started with.
let ipv6ChangedSince = null;
const IPV6_SETTLE_MS = 30_000;

const usage = new Usage();
try {
  usage.load(JSON.parse(await readFile(USAGE_FILE, 'utf8')));
} catch (error) {
  if (error.code !== 'ENOENT') log(`could not read the data use record, starting it over: ${error.message}`);
}
usage.keepOnly(settings.values.lines.map((line) => line.id));

// Routing should be on unless the person turned it off. While it should be on
// and isn't, it is started again, waiting longer after each failure.
let wantRouting = true;
const retry = { attempts: 0, at: 0 };

// Speed, through the routing engine and in either direction, above which a
// line counts as carrying traffic. The engine only sees internet traffic
// (local networks bypass it), so this is data really crossing the internet on
// that line; a few keep-alives stay well below it. Uploads count too: a line
// busy sending a big file is as slow to answer a test as one downloading.
const CARRYING_MIN_BYTES_PER_SECOND = 16 * 1024;

// One switch per line keeps its selector following the lines' health: its
// apps use the next line that works while it is down. Their look at the
// lines doesn't depend on the adapter scan, which can fail.
const lanes = new Map();

function syncLanes() {
  const lines = settings.values.lines;
  const ids = new Set(lines.map((line) => line.id));
  for (const id of lanes.keys()) if (!ids.has(id)) lanes.delete(id);
  for (const line of lines) {
    if (lanes.has(line.id)) continue;
    const id = line.id;
    lanes.set(
      id,
      new LaneSwitch({
        engine,
        lineId: id,
        getLines: () => settings.values.lines,
        isLineUp: (other) => lanes.get(other)?.isUp() ?? false,
        exhausted: () => exhaustedIds,
        usableAddresses,
        readDefaultRoutes,
        probe: (lineId, options) => engine.probe(lineId, { ...options, urls: probeUrls(settings.values.probeTargets) }),
        carryingTraffic: () => {
          const rate = tracker.lineRate(id);
          return rate.down >= CARRYING_MIN_BYTES_PER_SECOND || rate.up >= CARRYING_MIN_BYTES_PER_SECOND;
        },
        onChange: ({ up, reason }) => noteLineChange(id, up, reason),
        log: (text) => log(text),
      }),
    );
  }
}

function lineById(id) {
  return settings.values.lines.find((line) => line.id === id) ?? null;
}

function isLineUp(id) {
  return lanes.get(id)?.isUp() ?? false;
}

// Routing runs with a selector per line, so lines can stand in for each other.
function routingThroughLanes() {
  return engine.status === 'on' && (engine.startedWith?.lines?.length ?? 0) > 1;
}

function noteEvent(kind, lineId, text) {
  events.push({ id: randomBytes(6).toString('hex'), at: Date.now(), kind, lineId, text });
  if (events.length > EVENTS_KEPT) events.splice(0, events.length - EVENTS_KEPT);
}

const DOWN_REASONS = {
  'no address': 'it isn’t connected',
  'no default route': 'Windows has no internet route through it',
  'no internet': 'it doesn’t reach the internet',
};

function noteLineChange(id, up, reason) {
  const line = lineById(id);
  if (!line) return;
  if (up) noteEvent('up', id, `${line.label} is back.`);
  else noteEvent('down', id, `${line.label} is down: ${DOWN_REASONS[reason] ?? 'it doesn’t work right now'}.`);
}

syncLanes();

engine.on('status', (status) => {
  if (status !== 'on') {
    tracker.reset();
    outside.reset();
    for (const lane of lanes.values()) lane.reset({ sameLine: true });
    monitorFailures = 0;
    lineConnections = {};
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
// use; connections on any other adapter are on none of the lines.
monitor.on('sample', ({ outside: samples, at }) => {
  if (engine.status !== 'on') return;
  const owners = new Map();
  for (const line of settings.values.lines) {
    for (const address of adapters.find((item) => item.alias === line.alias)?.ipv4s ?? []) {
      if (!owners.has(address)) owners.set(address, line.id);
    }
  }
  // The engine's own outbound sockets also use the line addresses; they are
  // the routed traffic itself and must not be counted twice.
  const enginePid = engine.child?.pid;
  const relevant = samples
    .filter((sample) => sample.pid !== enginePid && owners.has(sample.local))
    .map((sample) => ({
      id: sample.id,
      path: sample.path,
      line: owners.get(sample.local),
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
  // A key set to undefined is removed.
  await settings.update({ setupUndo: undefined });
}

// Versions 0.2.0 and earlier knew two lines, the cable and a second
// connection; they become the first two lines. Lines a hand edit damaged are
// repaired or dropped, and pinned apps follow only lines that exist.
async function migrateLines() {
  const migration = migrateSettings(settings.values);
  if (migration) {
    await settings.update(migration);
    log(`settings moved to lines: ${settings.values.lines.map((line) => `${line.label} (${line.alias})`).join(', ') || 'none yet'}`);
  } else if (LEGACY_KEYS.some((key) => Object.hasOwn(settings.values, key))) {
    // Lines are already there: old keys a restored backup brought back mean nothing.
    await settings.update(withoutLegacyKeys());
  }
  const lines = normalizeLines(settings.values.lines);
  const ids = new Set(lines.map((line) => line.id));
  const appLines = Object.fromEntries(
    Object.entries(settings.values.appLines).filter(([programPath, id]) => programPath && typeof id === 'string' && ids.has(id)),
  );
  const combineMode = ['auto', 'manual'].includes(settings.values.combineMode) ? settings.values.combineMode : 'auto';
  const ipv6 = ['auto', 'off'].includes(settings.values.ipv6) ? settings.values.ipv6 : 'auto';
  const changed =
    JSON.stringify(lines) !== JSON.stringify(settings.values.lines) ||
    JSON.stringify(appLines) !== JSON.stringify(settings.values.appLines) ||
    combineMode !== settings.values.combineMode ||
    ipv6 !== settings.values.ipv6;
  if (changed) await settings.update({ lines, appLines, combineMode, ipv6 });
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
  // In the lane queue, like adding or removing a line, so a scan never
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
// (a driver update, a USB adapter in another port). Each line's adapter is
// also known by its id, so a renamed one is followed. A wired main line whose
// adapter is gone for good (a new driver gives it a new name and id) is moved
// to the wired adapter Windows now uses; any other line may just be unplugged
// for now, so it waits. With no lines yet, the adapter Windows uses for the
// internet becomes the main line. The supervisor then restarts routing so it
// binds the new names.
async function followAdapters() {
  const lines = settings.values.lines;
  if (lines.length === 0) {
    const picked = pickFirstAdapter(adapters);
    if (!picked) return;
    await settings.update({ lines: [newLine(picked, [])] });
    syncLanes();
    log(`${picked.alias} is the main line`);
    return;
  }
  const notes = [];
  // Adapters that are the same one under a new name, [from, to]: their Undo
  // records follow them. A replaced adapter is a different one, so its
  // record stays with the old name.
  const renamed = [];
  let changed = false;
  const next = lines.map((line, index) => {
    const found = findAdapter(adapters, { alias: line.alias, guid: line.guid });
    const missing = found ? 0 : (adapterMissing.get(line.id) ?? 0) + 1;
    adapterMissing.set(line.id, missing);
    if (found) {
      if (found.alias !== line.alias) {
        notes.push(`${line.label}'s adapter was renamed from ${line.alias} to ${found.alias}`);
        renamed.push([line.alias, found.alias]);
      }
      if (found.alias === line.alias && (!found.guid || found.guid === line.guid)) return line;
      changed = true;
      return { ...line, alias: found.alias, guid: found.guid || null };
    }
    if (index !== 0 || line.kind !== 'wired' || missing < ADAPTER_GONE_SCANS) return line;
    const taken = new Set(lines.map((item) => item.alias));
    const replacement = pickFirstAdapter(adapters.filter((item) => item.kind === 'wired' && !taken.has(item.alias)));
    if (!replacement) return line;
    notes.push(`${line.label}'s adapter ${line.alias} is gone; using ${replacement.alias} instead`);
    changed = true;
    return { ...line, alias: replacement.alias, guid: replacement.guid || null };
  });

  if (!changed) return;
  await settings.update({ lines: next });
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
  const bound = (lines) => JSON.stringify(lines.map(({ id, alias }) => [id, alias]));
  const differs = () => engine.startedWith && bound(engine.startedWith.lines) !== bound(settings.values.lines);
  if (differs()) {
    return inLaneQueue(async () => {
      if (!wantRouting || quitting || engine.status !== 'on' || !differs()) return;
      log(`routing restarts to use ${settings.values.lines.map((line) => line.alias).join(', ')}`);
      await restartEngine();
    });
  }
  // IPv6 came or went on a line. A restart is a short break for every app, so
  // only a change that lasts counts: an address can drop for a moment.
  const ipv6 = ipv6Wanted();
  if (!engine.startedWith || ipv6 === engine.startedWith.ipv6) {
    ipv6ChangedSince = null;
    return null;
  }
  ipv6ChangedSince ??= Date.now();
  if (Date.now() - ipv6ChangedSince < IPV6_SETTLE_MS) return null;
  ipv6ChangedSince = null;
  return inLaneQueue(async () => {
    if (!wantRouting || quitting || engine.status !== 'on' || ipv6Wanted() === engine.startedWith?.ipv6) return;
    log(ipv6 ? 'every line has IPv6 now: routing restarts to carry it too' : 'a line lost IPv6: routing restarts to keep apps on IPv4');
    await restartEngine();
  });
}

// IPv6 is routed only while every line has a global IPv6 address, and the
// person didn't turn it off. Test mode routes through a local proxy, where it
// makes no difference.
function ipv6Wanted() {
  const lines = settings.values.lines;
  return settings.values.ipv6 !== 'off' && lines.length > 0 && lines.every((line) => hasGlobalIPv6(line.alias));
}

// In priority order, so the main line's apps are placed first.
async function tickLanes() {
  for (const line of settings.values.lines) await lanes.get(line.id)?.tick();
}

// Data use per line for caps, and each line's top speed for Auto combining.
// Counted while routing is off too: a phone's data is used either way.
function noteUsage() {
  const lines = settings.values.lines;
  const now = Date.now();
  usage.ingest(lines, (line) => monitor.counters(line.alias), (line) => monitor.rate(line.alias)?.down ?? null, now);
  const next = usage.exhausted(lines, now);
  for (const line of lines) {
    if (next.has(line.id) && !exhaustedIds.has(line.id)) {
      noteEvent('exhausted', line.id, `${line.label} has used its data cap. Its apps use other lines until the cap resets.`);
      log(`${line.label} reached its data cap`);
    } else if (!next.has(line.id) && exhaustedIds.has(line.id)) {
      noteEvent('cap-reset', line.id, `${line.label} can be used again: its data cap has reset.`);
      log(`${line.label}'s data cap reset`);
    }
  }
  exhaustedIds = next;
}

async function saveUsage() {
  await writeFileAtomic(USAGE_FILE, JSON.stringify(usage.toJSON()));
}

// How combining shares new connections now: every line that may carry other
// lines' traffic takes part, by the weights the person set (manual) or by
// each line's measured top speed (auto). Empty with fewer than two.
function computeShares({ lines, combineMode } = settings.values) {
  const sharing = sharingLines(lines, exhaustedIds);
  if (sharing.length < 2) return {};
  const weights =
    combineMode === 'manual' ? Object.fromEntries(sharing.map((line) => [line.id, line.weight])) : usage.autoWeights(sharing);
  return sharesFromWeights(sharing, weights);
}

// Whether the rule files' shares should be rewritten: at once when a line
// joins or leaves sharing (it went out of data, or was kept to its own apps);
// in auto mode, at most once a minute and only for a real move, since every
// rewrite is a reload for the engine. Open connections never move either way.
function sharesOutdated(next) {
  const current = engine.shares;
  const ids = (shares) => Object.keys(shares).sort().join(',');
  if (ids(current) !== ids(next)) return true;
  const moved = (min) => Object.keys(next).some((id) => Math.abs(next[id] - current[id]) >= min);
  if (settings.values.combineMode !== 'auto') return moved(1e-9);
  return Date.now() - sharesWrittenAt >= AUTO_SHARE_EVERY_MS && moved(AUTO_SHARE_MIN_MOVE - 1e-9);
}

async function followShares() {
  if (!engine.combine) return;
  const next = computeShares();
  if (!sharesOutdated(next)) return;
  await engine.setShares(next);
  sharesWrittenAt = Date.now();
  log(`combining shares: ${Object.entries(next).map(([id, share]) => `${lineById(id)?.label ?? id} ${Math.round(share * 100)}%`).join(', ')}`);
}

// From the poll, without waiting: a line change may be holding the queue.
let sharesPending = false;
function followSharesSoon() {
  if (sharesPending || !engine.combine || !sharesOutdated(computeShares())) return;
  sharesPending = true;
  inLaneQueue(followShares)
    .catch((error) => log(`could not update combining's shares: ${error.message}`))
    .finally(() => {
      sharesPending = false;
    });
}

async function pollConnections() {
  syncLanes();
  // The window shows whether each line is connected, also while routing is off.
  for (const lane of lanes.values()) lane.sample();
  // A stalled monitor must not leave old speeds on screen.
  if (!monitor.isFresh()) outside.reset();
  noteUsage();
  if (engine.status !== 'on') return;
  // Each line's apps use the next working line while their own is down, and
  // their new connections go back as soon as it returns.
  await tickLanes();
  followSharesSoon();
  try {
    const connections = await engine.connections();
    monitorFailures = 0;
    tracker.ingest(connections, Date.now());
    lineConnections = {};
    for (const connection of connections) {
      const id = connectionLine(connection);
      if (id) lineConnections[id] = (lineConnections[id] ?? 0) + 1;
    }
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
    await engine.start({ lines: settings.values.lines, ipv6: ipv6Wanted() });
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

// One change at a time. The engine's rule files are the routing truth, so they
// are written first; the saved choice follows, and is rolled back if saving
// fails. Reports back only once sing-box has reloaded the rules.
// lineId: the line the app is pinned to, or null for the default: the main
// line, or every sharing line while combining. An app pinned to the main line
// stays on it even while combining.
function setAppLine(processPath, lineId) {
  return inLaneQueue(async () => {
    if (typeof processPath !== 'string' || processPath === '' || (lineId !== null && typeof lineId !== 'string')) {
      throw clientError('Choose an app and a line, then try again.');
    }
    if (lineId !== null && !lineById(lineId)) throw clientError('That line isn’t there any more.');
    const previous = settings.values.appLines;
    const key = appKey(processPath);
    const appLines = Object.fromEntries(Object.entries(previous).filter(([item]) => appKey(item) !== key));
    if (lineId !== null) appLines[processPath] = lineId;
    await engine.setAppLines(appLines);
    try {
      await settings.update({ appLines });
    } catch (error) {
      await engine.setAppLines(previous).catch(() => {});
      throw error;
    }
    await delay(RULE_RELOAD_MS);
  });
}

// The line an app is pinned to, if it is and that line exists.
function pinnedLine(key) {
  const id = appPins(settings.values.appLines).get(key)?.lineId;
  return id && lineById(id) ? id : null;
}

// Where a line's apps' new connections go now: the line itself, or the line
// standing in for it while it is down.
function laneTargetNow(id) {
  if (!routingThroughLanes()) return id;
  return lanes.get(id)?.target ?? id;
}

// New connections are really being split: the engine's rules combine, routing
// is on, and at least two sharing lines carry their own traffic. While a line
// is down, its share goes where its apps go.
function combineActive() {
  if (!engine.combine || engine.status !== 'on') return false;
  return Object.keys(engine.shares).filter((id) => engine.shares[id] > 0 && laneTargetNow(id) === id).length >= 2;
}

// Combining is a rule file per line, so it turns on and off, and its shares
// change, without restarting routing. Like an app's line, it applies to new
// connections. weights: { [lineId]: number } for manual mode.
function setCombine({ on, mode: combineMode, weights }) {
  return inLaneQueue(async () => {
    if (on !== undefined && typeof on !== 'boolean') throw clientError('Choose whether to combine the lines, then try again.');
    if (combineMode !== undefined && !['auto', 'manual'].includes(combineMode)) {
      throw clientError('Choose Auto or Manual, then try again.');
    }
    if (weights !== undefined && (weights === null || typeof weights !== 'object' || Array.isArray(weights))) {
      throw clientError('Set how much each line takes, then try again.');
    }
    const lines = settings.values.lines.map((line) => {
      const weight = weights?.[line.id];
      if (weight === undefined) return line;
      if (typeof weight !== 'number' || !Number.isFinite(weight) || weight < 0 || weight > 1000) {
        throw clientError('Set how much each line takes, then try again.');
      }
      return { ...line, weight };
    });
    const next = {
      lines,
      combine: on ?? settings.values.combine,
      combineMode: combineMode ?? settings.values.combineMode,
    };
    // A line out of data still counts, as it will share again once its cap resets.
    if (next.combine && sharingLines(lines).length < 2) {
      throw clientError('Combining needs two lines that any app may use. Add a line, or let one take any app.');
    }
    const shares = computeShares(next);
    const previous = { combine: engine.combine, shares: engine.shares };
    await engine.changeRules({ combine: next.combine, shares });
    try {
      await settings.update(next);
    } catch (error) {
      await engine.changeRules(previous).catch((undo) => log(`combining was left changed after a failed save: ${undo.message}`));
      throw error;
    }
    sharesWrittenAt = Date.now();
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
    const programPath = tracker.snapshot().find((row) => row.key === key)?.path ?? outside.get(key)?.path ?? '';
    if (!appInfo.describe(programPath).reconnectable) {
      throw clientError('This one can’t be reconnected, because other programs share its connections.');
    }
    // Its new connections go to its line, or to the one standing in for it
    // while that line is down: there is where the old ones belong too. When
    // a line comes back, nothing is closed by itself, so this is how an app's
    // connections return at once.
    const pinned = pinnedLine(key);
    const home = pinned ?? settings.values.lines[0]?.id;
    const target = home ? laneTargetNow(home) : null;
    if (!target || !isLineUp(target)) {
      throw clientError(`${lineById(home)?.label ?? 'Its line'} isn’t connected, so there’s nowhere to move it yet.`);
    }
    // While combining splits traffic, every sharing line is right for an app
    // that shares them: only its connections that go around routing are out
    // of place. An app pinned to a line doesn't share.
    const shared = !pinned && combineActive();
    let closed = 0;
    let failed = 0;
    // Routed connections: the engine's own count, from the last poll.
    for (const id of shared ? [] : tracker.connectionIdsOffLine(key, target)) {
      try {
        await engine.closeConnection(id);
        closed += 1;
      } catch {
        failed += 1;
      }
    }
    // Connections around routing, but only those not already on the right line.
    const outsideIds = shared ? outside.idsOf(key) : outside.idsOffLine(key, target);
    const result = await closeTcpConnections(outsideIds.map(parseOutsideId).filter(Boolean));
    closed += result.closed;
    failed += result.failed;
    await log(`reconnect ${key}: closed ${closed}, failed ${failed} (codes ${result.codes.join(',')}), already gone ${result.gone}`);
    return { closed, failed, gone: result.gone };
  });
}

// Adding, removing and reordering lines changes what routing binds, so each
// restarts it; they wait behind any pending line change. Renaming a line,
// keeping it to its own apps and its data cap are decided here, so they apply
// at once without a restart.

function knownLine(id) {
  const line = typeof id === 'string' ? lineById(id) : null;
  if (!line) throw clientError('That line isn’t there any more.');
  return line;
}

// The main line carries every app without a choice, so it can't be kept to
// its own apps; a line that becomes the main one loses that.
function withMainOpen(lines) {
  return lines.map((line, index) => (index === 0 && line.strict ? { ...line, strict: false } : line));
}

// Combining stays on only while two lines may share. A line out of data still
// counts: that lasts only until its cap resets, and combining picks it up again.
function combineStillPossible(lines) {
  return settings.values.combine && sharingLines(lines).length >= 2;
}

async function applyLines(lines, appLines = settings.values.appLines) {
  const combine = combineStillPossible(lines);
  const next = { lines, appLines, combine };
  const previous = { appLines: engine.appLines, combine: engine.combine, shares: engine.shares };
  await engine.changeRules({ appLines, combine, shares: computeShares({ ...settings.values, ...next }) });
  try {
    await settings.update(next);
  } catch (error) {
    await engine.changeRules(previous).catch(() => {});
    throw error;
  }
  usage.keepOnly(lines.map((line) => line.id));
  syncLanes();
}

function addLine(alias) {
  return inLaneQueue(async () => {
    const lines = settings.values.lines;
    const adapter = typeof alias === 'string' ? adapters.find((item) => item.alias === alias && item.connected) : null;
    // Test mode may use one adapter twice, to check routing without a second network.
    const taken = lines.some((line) => line.alias === alias) && mode !== 'proxy';
    if (!adapter || taken) throw clientError('That connection isn’t available. Check that it’s connected, then try again.');
    if (lines.length >= MAX_LINES) throw clientError(`Net Switch can use up to ${MAX_LINES} lines.`);
    const line = newLine(adapter, lines);
    await applyLines([...lines, line]);
    log(`added ${line.label} (${line.alias})`);
    if (engine.status !== 'off') await restartEngine();
  });
}

// Apps pinned to a removed line go back to the default.
function removeLine(id) {
  return inLaneQueue(async () => {
    const line = knownLine(id);
    const lines = settings.values.lines;
    if (lines.length === 1) throw clientError('Net Switch needs at least one line.');
    const appLines = Object.fromEntries(Object.entries(settings.values.appLines).filter(([, lineId]) => lineId !== id));
    await applyLines(withMainOpen(lines.filter((item) => item.id !== id)), appLines);
    adapterMissing.delete(id);
    log(`removed ${line.label} (${line.alias})`);
    if (engine.status !== 'off') await restartEngine();
  });
}

// ids: every line's id, in the new priority order; the first is the main line.
function orderLines(ids) {
  return inLaneQueue(async () => {
    const lines = settings.values.lines;
    const valid =
      Array.isArray(ids) && ids.length === lines.length && new Set(ids).size === ids.length && ids.every((id) => lineById(id));
    if (!valid) throw clientError('The lines changed meanwhile. Try again.');
    await applyLines(withMainOpen(ids.map((id) => lineById(id))));
    log(`line order: ${settings.values.lines.map((line) => line.label).join(', ')}`);
    if (engine.status !== 'off') await restartEngine();
  });
}

// changes: { label?, metered?, strict?, cap? }; cap is { bytes, period, resetDay } or null.
function updateLine(id, changes) {
  return inLaneQueue(async () => {
    const line = knownLine(id);
    const main = settings.values.lines[0].id === id;
    const next = { ...line };
    if (changes.label !== undefined) {
      const label = typeof changes.label === 'string' ? changes.label.trim() : '';
      if (!label || label.length > MAX_LABEL_LENGTH) throw clientError(`Give the line a name of up to ${MAX_LABEL_LENGTH} characters.`);
      next.label = label;
    }
    if (changes.metered !== undefined) {
      if (typeof changes.metered !== 'boolean') throw clientError('Choose whether this line costs data, then try again.');
      next.metered = changes.metered;
    }
    if (changes.strict !== undefined) {
      if (typeof changes.strict !== 'boolean') throw clientError('Choose which apps may use this line, then try again.');
      if (changes.strict && main) {
        throw clientError('The main line carries every app without a line of its own, so it can’t be kept to chosen apps.');
      }
      next.strict = changes.strict;
    }
    if (changes.cap !== undefined) {
      const cap = changes.cap === null ? null : validCap(changes.cap);
      if (changes.cap !== null && !cap) throw clientError('Set the data cap as an amount per day or per month, then try again.');
      next.cap = cap;
    }
    // Whether the line is out of data, and where its apps go, follows at the
    // next poll, a second later.
    await applyLines(settings.values.lines.map((item) => (item.id === id ? next : item)));
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
// The other lines' adapters Windows would prefer over the main line's, or use
// as much, when Net Switch is off.
function outrankingMain() {
  const [first, ...rest] = settings.values.lines;
  const main = first ? adapters.find((item) => item.alias === first.alias && item.connected) : null;
  if (!main) return { main: null, others: [] };
  const others = rest
    .map((line) => adapters.find((item) => item.alias === line.alias && item.connected))
    .filter((item) => item && item.alias !== main.alias && effectiveMetric(item) <= effectiveMetric(main));
  return { main, others };
}

// Makes Windows prefer the main line while Net Switch is off: every other
// line that Windows would use first gets a clearly higher metric.
function makeMainTheDefault() {
  return inSetupQueue(async () => {
    const { main, others } = outrankingMain();
    if (!main || others.length === 0) throw clientError('Connect the main line and the others, then try again.');
    for (const other of others) {
      // An empty record, from versions that saved a failed reading, holds nothing to restore.
      if (!windowsUndo.values.metrics[other.alias]?.length) {
        let before;
        try {
          before = await readMetrics(other.alias);
        } catch (error) {
          log(`could not read ${other.alias}'s settings before changing them: ${error.message}`);
          throw clientError('Windows didn’t say how this connection is set up now, so Net Switch can’t change it safely. Try again in a moment.');
        }
        await windowsUndo.update((values) => ({ metrics: { ...values.metrics, [other.alias]: before } }));
      }
      await applyCableAsMain(main, other, windowsUndo.values.metrics[other.alias]);
    }
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

// ---------------------------------------------------------------- settings

const MAX_PROBE_TARGETS = 4;
const PROBE_TARGET = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3}):(\d{1,5})$/;

// address:port, IPv4 only: the quick check connects from each line's IPv4
// address, and a name would be looked up through whichever line Windows prefers.
function validProbeTarget(target) {
  const match = typeof target === 'string' ? PROBE_TARGET.exec(target.trim()) : null;
  if (!match) return false;
  const port = Number(match[5]);
  return match.slice(1, 5).every((part) => Number(part) <= 255) && port >= 1 && port <= 65535;
}

// Starting with Windows needs an installed copy (see lib/autostart.mjs), and
// test mode, which runs beside the real one, never touches it.
const AUTOSTART_ALLOWED = !testMode && USER_DIR !== DEFAULT_DIR && canAutostart({ root: ROOT, nodePath: process.execPath });
// Whether the startup task is there, or null while unknown.
let autostart = null;

async function refreshAutostart() {
  if (!AUTOSTART_ALLOWED) return;
  autostart = await readAutostart().catch((error) => {
    log(`could not read whether Net Switch starts with Windows: ${describeFailure(error, 10_000)}`);
    return autostart;
  });
}

// In the setup queue, like the other changes to Windows.
function setAutostart(on) {
  return inSetupQueue(async () => {
    if (!AUTOSTART_ALLOWED) throw clientError('Starting with Windows needs Net Switch installed from its installer.');
    try {
      if (on) {
        await enableAutostart({ root: ROOT, nodePath: process.execPath, userDir: USER_DIR, machineDir: MACHINE_DIR });
      } else {
        await disableAutostart();
      }
    } catch (error) {
      log(`could not turn starting with Windows ${on ? 'on' : 'off'}: ${describeFailure(error, 30_000)}`);
      throw clientError(`Windows didn’t accept the change. Try again in a moment.`);
    } finally {
      await refreshAutostart();
    }
    log(`starting with Windows is ${on ? 'on' : 'off'}`);
  });
}

// changes: { autostart?, checkForUpdates?, probeTargets? }; missing ones stay.
async function changeSettings({ autostart: startWithWindows, checkForUpdates, probeTargets }) {
  if (checkForUpdates !== undefined && typeof checkForUpdates !== 'boolean') {
    throw clientError('Choose whether to check for updates, then try again.');
  }
  if (startWithWindows !== undefined && typeof startWithWindows !== 'boolean') {
    throw clientError('Choose whether Net Switch starts with Windows, then try again.');
  }
  let targets;
  if (probeTargets !== undefined) {
    if (!Array.isArray(probeTargets) || probeTargets.length === 0 || probeTargets.length > MAX_PROBE_TARGETS || !probeTargets.every(validProbeTarget)) {
      throw clientError(`Enter one to ${MAX_PROBE_TARGETS} test addresses as address:port, like 1.1.1.1:443.`);
    }
    targets = [...new Set(probeTargets.map((target) => target.trim()))];
  }
  if (startWithWindows !== undefined) await setAutostart(startWithWindows);
  await settings.update({
    ...(checkForUpdates !== undefined ? { checkForUpdates } : {}),
    ...(targets ? { probeTargets: targets } : {}),
  });
  if (checkForUpdates === true) await updates.check();
  else if (checkForUpdates === false) updates.offer = null;
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
      await saveUsage().catch((error) => log(`could not save the data use record: ${error.message}`));
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

function lineState(line, index) {
  const adapter = adapters.find((item) => item.alias === line.alias) ?? null;
  const lane = lanes.get(line.id);
  const health = lane?.health;
  const target = engine.status === 'on' ? laneTargetNow(line.id) : null;
  return {
    id: line.id,
    alias: line.alias,
    label: line.label,
    kind: line.kind ?? adapter?.kind ?? null,
    main: index === 0,
    connected: lane?.isUp() ?? false,
    // Why the line counts as down, while it does: 'no address', 'no default
    // route', 'no internet', or 'checking' (connected again, waiting for a
    // test to pass).
    problem: health?.up === false ? health.reason : null,
    // Round trip in ms of the last passing test, while the line counts as up
    // (only tested while routing runs with two lines or more).
    ping: health?.up === true ? lane.delay : null,
    connections: lineConnections[line.id] ?? 0,
    // Whether its own apps' new connections go to it now, and the line they
    // go to: another one while it is down.
    carrying: target === line.id,
    target,
    // Real speed from Windows, including traffic that goes around routing.
    // No fallback to the engine's own count: that misses exactly this traffic.
    rate: monitor.rate(line.alias),
    ssid: adapter?.ssid || null,
    metered: line.metered,
    strict: line.strict,
    cap: line.cap,
    usage: usage.used(line.id),
    exhausted: exhaustedIds.has(line.id),
    weight: line.weight,
    // Its part of new connections while combining, from the rule files.
    share: engine.combine ? (engine.shares[line.id] ?? 0) : null,
  };
}

function buildState() {
  const lines = settings.values.lines;
  const { appLines } = settings.values;
  const routingOn = engine.status === 'on';
  const measuring = routingOn && monitorFailures < MONITOR_FAILURE_LIMIT;
  const wifiPresent = adapters.some((item) => item.kind === 'wifi');
  const undo = windowsUndo.values;

  const apps = mergeRows(tracker.snapshot(appLines), outside, appLines).map((app) => {
    const info = appInfo.describe(app.path);
    return {
      key: app.key,
      path: app.path,
      name: info.name,
      hasIcon: info.hasIcon,
      switchable: info.switchable,
      reconnectable: info.reconnectable,
      line: app.line,
      rate: app.rate,
      lineDown: app.lineDown,
      sortScore: app.sortScore,
      connections: app.connections,
      outside: app.outside,
    };
  });

  return {
    mode,
    elevated,
    version: APP_VERSION,
    // A newer release to offer ({ version, page, installer }) or null, and
    // whether checking is on, for the switch in the window.
    update: updateOffer(),
    updateChecks: !testMode && settings.values.checkForUpdates,
    features: { reconnect: true, combine: true, lines: true, installedApps: true },
    // From the engine's rules rather than the saved choice, so the window
    // shows what routing really does even if saving the choice failed.
    combine: { on: engine.combine, active: combineActive(), mode: settings.values.combineMode },
    routing: {
      status: engine.status,
      // Whether the person wants routing on. While a start is failing it is
      // still true, and the window offers Turn off to stop the retries.
      wanted: wantRouting,
      error: engine.error,
      measuring,
      proxyPort: engine.proxyPort,
      // Whether IPv6 is routed too (every line has it), or refused so apps use IPv4.
      ipv6: routingOn ? Boolean(engine.startedWith?.ipv6) : null,
      // When routing that should be on is started again by itself.
      retryAt: wantRouting && engine.status === 'error' && (mode !== 'tun' || elevated) ? retry.at : null,
    },
    // In priority order: the first is the main line.
    lines: lines.map(lineState),
    // Connected adapters that aren't a line yet, to add as one.
    candidates: adapters
      .filter((item) => item.connected && !lines.some((line) => line.alias === item.alias))
      .map((item) => ({ alias: item.alias, label: lineLabel(item), kind: item.kind, ssid: item.ssid || null })),
    apps,
    events,
    settings: {
      // Whether Net Switch starts with Windows; null when this copy can't
      // (a source checkout, test mode) or it couldn't be read yet.
      autostart: AUTOSTART_ALLOWED ? autostart : null,
      checkForUpdates: !testMode && settings.values.checkForUpdates,
      probeTargets: settings.values.probeTargets,
    },
    setup: {
      // Windows would use another line before the main one while Net Switch is off.
      cableNotDefault: outrankingMain().others.length > 0,
      // Policy 3 blocks even connecting Wi-Fi by hand while a cable is plugged in.
      wifiBlocked: minimizePolicy === 3 && wifiPresent,
      keepBothConnected: Boolean(
        lines.length > 1 &&
          lines.some((line) => (line.kind ?? adapters.find((item) => item.alias === line.alias)?.kind) === 'wifi') &&
          minimizePolicy !== 0 &&
          minimizePolicy !== 3,
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
  'GET /api/installed-apps': async () => installedApps.list(),
  'POST /api/routing': async ({ on }) => {
    await setRouting(Boolean(on));
    return buildState();
  },
  'POST /api/app-line': async ({ path: processPath, line }) => {
    await setAppLine(processPath, line ?? null);
    return buildState();
  },
  'POST /api/lines/add': async ({ alias }) => {
    await addLine(alias);
    return buildState();
  },
  'POST /api/lines/remove': async ({ id }) => {
    await removeLine(id);
    return buildState();
  },
  'POST /api/lines/update': async ({ id, label, metered, strict, cap }) => {
    await updateLine(id, { label, metered, strict, cap });
    return buildState();
  },
  'POST /api/lines/order': async ({ ids }) => {
    await orderLines(ids);
    return buildState();
  },
  'POST /api/reconnect': async ({ key }) => ({ ...(await reconnectApp(key)), state: buildState() }),
  // "Not now" for one release: it isn't offered again, a later one is.
  'POST /api/update/dismiss': async ({ version }) => {
    if (typeof version !== 'string' || !version) throw clientError('Choose which update to skip, then try again.');
    await settings.update({ skippedUpdate: version });
    return buildState();
  },
  'POST /api/combine': async ({ on, mode: combineMode, weights }) => {
    await setCombine({ on, mode: combineMode, weights });
    return buildState();
  },
  'POST /api/settings': async ({ autostart, checkForUpdates, probeTargets }) => {
    await changeSettings({ autostart, checkForUpdates, probeTargets });
    return buildState();
  },
  // The path is from when the main line was always the cable.
  'POST /api/setup/cable-default': async () => {
    await makeMainTheDefault();
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
await refreshAutostart();
// The rule files are written for these when routing starts.
await engine.changeRules({
  appLines: settings.values.appLines,
  combine: Boolean(settings.values.combine),
  shares: computeShares(),
});
// Swapped in whole, so the launcher and the tray never read half of it.
await writeFileAtomic(SERVER_FILE, JSON.stringify({ port, token, pid: process.pid, mode, startedAt: new Date().toISOString() }));
await log(`started on port ${port} (mode ${mode}, elevated ${elevated})`);
console.log(`Net Switch is running at http://127.0.0.1:${port}/#token=${token}`);

monitor.start();
updates.start();
every(nextScanDelay, refreshAdapters);
every(1000, pollConnections);
every(1000, superviseRouting);
every(USAGE_SAVE_EVERY_MS, saveUsage);
