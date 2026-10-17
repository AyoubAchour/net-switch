import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import path from 'node:path';
import { before, test } from 'node:test';
import { fileURLToPath } from 'node:url';

// The tray icon's logic is C# (lib/tray.cs), compiled by Windows PowerShell 5.1
// the same way tray.ps1 compiles it. All cases run in one PowerShell call.
const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), '..');
const POWERSHELL = path.join(process.env.SystemRoot ?? 'C:\\Windows', 'System32', 'WindowsPowerShell', 'v1.0', 'powershell.exe');

const RUNNER = String.raw`
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
[Console]::OutputEncoding = [Text.Encoding]::UTF8
Add-Type -Path $env:NETSWITCH_TRAY_CS -ReferencedAssemblies System.Windows.Forms, System.Drawing, System.Net.Http, System.Web.Extensions
$json = New-Object System.Web.Script.Serialization.JavaScriptSerializer
$results = foreach ($case in $json.DeserializeObject($env:NETSWITCH_CASES)) {
  switch ($case['kind']) {
    'flyout' { [NetSwitch.FlyoutModel]::FromState($case['state']) }
    'flyoutRate' { @{ lit = [NetSwitch.FlyoutModel]::Lit([double]$case['value']) } }
    'rate' { @{ text = [NetSwitch.TrayModel]::Rate([double]$case['value']); lit = [NetSwitch.TrayModel]::Lit([double]$case['value']) } }
    default {
      $view = switch ($case['kind']) {
        'state' { [NetSwitch.TrayModel]::FromState($case['state']) }
        'unreachable' { [NetSwitch.TrayModel]::Unreachable([bool]$case['running']) }
        'quitting' { [NetSwitch.TrayModel]::Quitting() }
      }
      $bitmap = [NetSwitch.TrayPainter]::Paint($view, 16)
      # A corner, the panel between the rows, the first and last cable cells, the first second-line cell.
      $pixels = foreach ($point in @(@(0, 0), @(8, 7), @(1, 3), @(13, 3), @(1, 9))) { '{0:x8}' -f $bitmap.GetPixel($point[0], $point[1]).ToArgb() }
      $bitmap.Dispose()
      @{ tooltip = [NetSwitch.TrayModel]::Tooltip($view); icon = [NetSwitch.TrayModel]::IconSignature($view); pixels = @($pixels) }
    }
  }
}
$json.Serialize(@($results))
`;

const lane = (label, connected, rate) => ({ label, connected, rate });
const state = ({ status = 'on', mode = 'tun', main = lane('Cable', true, { down: 6098, up: 6916 }), second } = {}) => ({
  kind: 'state',
  state: {
    mode,
    routing: { status },
    lanes: { main, second: second === undefined ? lane('Wi-Fi stick', true, { down: 937_439, up: 0 }) : second },
  },
});

const app = (name, score, down = score, extra = {}) => ({ name, path: `C:\\Apps\\${name}.exe`, lane: 'main', switchable: true, sortScore: score, rate: { down, up: 0 }, ...extra });
const flyout = (overrides = {}) => ({ kind: 'flyout', state: { ...state().state, apps: [], ...overrides } });
const cable = { ...lane('Cable', true, { down: 38 * 1024, up: 1234 }), alias: 'Ethernet', carryingApps: true, ping: 18 };
const wifi = { ...lane('Wi-Fi stick', true, { down: 915 * 1024, up: 50 }), alias: 'Wi-Fi 2', ssid: 'Home', kind: 'wifi', carryingApps: true, ping: null };

const CASES = {
  flyoutOn: flyout({ lanes: { main: cable, second: wifi } }),
  flyoutOff: flyout({ routing: { status: 'off', wanted: false } }),
  flyoutError: flyout({ routing: { status: 'error', wanted: true } }),
  flyoutStarting: flyout({ routing: { status: 'starting', wanted: true } }),
  flyoutStopping: flyout({ routing: { status: 'stopping', wanted: false } }),
  flyoutCombine: flyout({ combine: { on: true } }),
  flyoutKept: flyout({
    combine: { on: true },
    features: { cableOnly: true },
    apps: [app('Calls', 30, 30, { cableOnly: true }), app('Browser', 20), app('Game', 10, 10, { lane: 'second' })],
  }),
  flyoutKeptNoCombine: flyout({ features: { cableOnly: true }, apps: [app('Calls', 30, 30, { cableOnly: true })] }),
  flyoutMissing: flyout({ lanes: { main: cable, second: null }, combine: { on: true }, apps: [app('Browser', 50)] }),
  flyoutNoMove: flyout({ apps: [app('Windows', 80, 80, { switchable: false, lane: 'second' })] }),
  flyoutTop: flyout({ apps: [app('Idle', 999, 0), app('Fourth', 10), app('Third', 20), app('First', 50), app('Second', 30)] }),
  flyoutIdle: flyout({ apps: [app('Zed', 5, 0), app('Alpha', 5, 0), app('Busy before', 10, 0)] }),
  flyoutUpload: flyout({ apps: [app('Sending', 5, 0, { rate: { down: 0, up: 1024 } }), app('Idle', 10, 0)] }),
  flyoutSecondDown: flyout({ lanes: { main: cable, second: { ...wifi, connected: false, problem: 'no internet', carryingApps: false } } }),
  flyoutMainDown: flyout({ lanes: { main: { ...cable, problem: 'no address', carryingApps: false }, second: wifi } }),
  flyoutBothDown: flyout({ lanes: { main: { ...cable, connected: false, carryingApps: false }, second: { ...wifi, problem: 'no internet', carryingApps: false } } }),
  flyoutNoFallback: flyout({ lanes: { main: { ...cable, carryingApps: false }, second: { ...wifi, problem: 'no default route', carryingApps: false } } }),
  flyoutMainRecovering: flyout({ lanes: { main: { ...cable, carryingApps: false }, second: wifi } }),
  flyoutSecondRecovering: flyout({ lanes: { main: cable, second: { ...wifi, carryingApps: false } } }),
  flyoutSingleDown: flyout({ lanes: { main: { ...cable, connected: false, problem: 'no address' }, second: null } }),
  flyoutPhone: flyout({ lanes: { main: cable, second: { ...wifi, kind: 'tether', label: 'USB phone' } } }),
  flyoutLong: flyout({ lanes: { main: cable, second: { ...wifi, kind: 'ethernet', label: 'Second ethernet adapter' } } }),
  flyoutOld: flyout({ routing: { status: 'on' }, lanes: { main: lane('Cable', true, null), second: lane('Wi-Fi stick', true, null) } }),
  flyoutUnavailable: { kind: 'flyout', state: null },
  flyoutRateZero: { kind: 'flyoutRate', value: 0 },
  flyoutRate1k: { kind: 'flyoutRate', value: 1024 },
  flyoutRate1m: { kind: 'flyoutRate', value: 1024 * 1024 },
  flyoutRate10m: { kind: 'flyoutRate', value: 10 * 1024 * 1024 },
  routingOn: state(),
  routingOff: state({ status: 'off' }),
  stopped: state({ status: 'error' }),
  notSetUp: state({ second: null }),
  secondDown: state({ second: lane('Wi-Fi stick', false, null) }),
  noSpeed: state({ main: lane('Cable', true, null) }),
  uploadOnly: state({ second: lane('Phone', true, { down: 0, up: 2_000_000 }) }),
  testMode: state({ mode: 'proxy' }),
  longLabel: state({
    status: 'stopping',
    second: lane('Realtek USB GbE Family Controller #2', true, { down: 123_456_789, up: 123_456_789 }),
  }),
  stuck: { kind: 'unreachable', running: true },
  gone: { kind: 'unreachable', running: false },
  quitting: { kind: 'quitting' },
  rate0: { kind: 'rate', value: 0 },
  rateTiny: { kind: 'rate', value: 1000 },
  rate1k: { kind: 'rate', value: 1024 },
  rateTop: { kind: 'rate', value: 1_048_575 },
  rate1m: { kind: 'rate', value: 1_048_576 },
  rate10m: { kind: 'rate', value: 10 * 1_048_576 },
};

const AMBER = 'fff0b23e';
const GRAY = 'ffa8adb3';
const PANEL = 'ff141619';
const CLEAR = '00000000';

let results;

before(() => {
  const encoded = Buffer.from(RUNNER, 'utf16le').toString('base64');
  let output;
  try {
    output = execFileSync(POWERSHELL, ['-NoProfile', '-NonInteractive', '-OutputFormat', 'Text', '-EncodedCommand', encoded], {
      env: { ...process.env, NETSWITCH_TRAY_CS: path.join(ROOT, 'lib', 'tray.cs'), NETSWITCH_CASES: JSON.stringify(Object.values(CASES)) },
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'pipe'],
      windowsHide: true,
      timeout: 60_000,
    });
  } catch (error) {
    // Keep the compiler's file and line, without burying it under the encoded runner.
    throw new Error(`Tray compilation or model checks failed:\n${error.stderr || error.message}`);
  }
  const list = JSON.parse(output.trim());
  results = Object.fromEntries(Object.keys(CASES).map((name, index) => [name, list[index]]));
});

test('the tooltip names the routing state and both lines with the window’s speed wording', () => {
  assert.equal(
    results.routingOn.tooltip,
    'Net Switch: routing is on\nCable: ↓ 6 KB/s  ↑ 7 KB/s\nWi-Fi stick: ↓ 915 KB/s  ↑ 0 KB/s',
  );
  assert.match(results.routingOff.tooltip, /^Net Switch: routing is off\n/);
  assert.match(results.stopped.tooltip, /^Net Switch: routing stopped\n/);
  assert.match(results.testMode.tooltip, /^Net Switch: routing is on \(test mode\)\n/);
});

test('a missing, disconnected or unmeasured line says so instead of showing zero', () => {
  assert.match(results.notSetUp.tooltip, /\nSecond connection: not set up$/);
  assert.match(results.secondDown.tooltip, /\nWi-Fi stick: not connected$/);
  assert.match(results.noSpeed.tooltip, /\nCable: speed not available\n/);
});

test('when Net Switch can’t be reached, the tooltip says what happened and what a click does', () => {
  assert.equal(results.stuck.tooltip, 'Net Switch isn’t responding\nClick for Open Net Switch.');
  assert.equal(results.gone.tooltip, 'Net Switch isn’t running\nClick for Open Net Switch.');
  assert.equal(results.quitting.tooltip, 'Net Switch is quitting…');
});

test('long labels and big speeds still fit the 127 characters Windows allows', () => {
  const tip = results.longLabel.tooltip;
  assert.ok(tip.length <= 127, `${tip.length} characters`);
  assert.match(tip, /^Net Switch: turning off routing…\n/);
  assert.match(tip, /\nRealtek USB GbE F…: ↓ 117\.7 MB\/s {2}↑ 117\.7 MB\/s$/);
});

test('speeds read like the window and light cells on its scale', () => {
  assert.deepEqual(results.rate0, { text: '0 KB/s', lit: 0 });
  assert.deepEqual(results.rateTiny, { text: '<1 KB/s', lit: 1 });
  assert.deepEqual(results.rate1k, { text: '1 KB/s', lit: 1 });
  assert.equal(results.rateTop.text, '1024 KB/s');
  assert.equal(results.rate1m.text, '1.0 MB/s');
  assert.deepEqual(results.rate10m, { text: '10.0 MB/s', lit: 5 });
});

test('each icon row lights for its line’s download and upload together', () => {
  // 13 KB/s on the cable lights one cell, 915 KB/s on the Wi-Fi stick four.
  assert.equal(results.routingOn.icon, 'on|True1|True4');
  // Upload alone still lights the row.
  assert.equal(results.uploadOnly.icon, 'on|True1|True4');
  assert.equal(results.noSpeed.icon, 'on|True0|True4');
  assert.equal(results.notSetUp.icon, 'on|True1|False0');
  assert.equal(results.stuck.icon, 'off|False0|False0');
});

test('the icon keeps the line colors only while routing is on, on the dark panel with clear corners', () => {
  const [corner, panel, firstCable, lastCable] = results.routingOn.pixels;
  assert.equal(corner, CLEAR);
  assert.equal(panel, PANEL);
  assert.equal(firstCable, AMBER);
  // One lit cell: the last cable cell is the dim, unlit kind.
  assert.notEqual(lastCable, AMBER);
  assert.equal(results.routingOff.pixels[2], GRAY);
});

test('the flyout totals downloads, describes routing, and uses wanted even during a failed start', () => {
  assert.equal(results.flyoutOn.Status, 'Routing on · 953 KB/s');
  assert.equal(results.flyoutOn.TotalDown, 953 * 1024);
  assert.equal(results.flyoutOn.Tone, 'ok');
  assert.equal(results.flyoutOn.RoutingWanted, true);
  assert.match(results.flyoutOff.Status, /^Routing off · /);
  assert.equal(results.flyoutOff.RoutingWanted, false);
  assert.equal(results.flyoutOff.Tone, 'dim');
  assert.match(results.flyoutError.Status, /^Routing stopped · /);
  assert.equal(results.flyoutError.RoutingWanted, true);
  assert.equal(results.flyoutError.Tone, 'error');
  assert.match(results.flyoutStarting.Status, /^Starting routing… · /);
  assert.match(results.flyoutStopping.Status, /^Turning routing off… · /);
});

test('the flyout picks the top three by score, keeps idle rows only when all are idle, and includes uploads', () => {
  assert.deepEqual(results.flyoutTop.Apps.map(a => a.Name), ['First', 'Second', 'Third']);
  assert.deepEqual(results.flyoutIdle.Apps.map(a => a.Name), ['Busy before', 'Alpha', 'Zed']);
  assert.deepEqual(results.flyoutUpload.Apps.map(a => a.Name), ['Sending']);
  assert.equal(results.flyoutTop.Apps[0].Speed, '<1 KB/s');
  assert.equal(results.flyoutTop.Apps[0].Initial, 'F');
});

test('the flyout labels app options and disables unsupported changes', () => {
  assert.equal(results.flyoutOn.MainOption, 'Cable');
  assert.equal(results.flyoutCombine.MainOption, 'Both');
  assert.equal(results.flyoutOn.SecondOption, 'Wi-Fi');
  assert.equal(results.flyoutPhone.SecondOption, 'Phone');
  assert.equal(results.flyoutLong.SecondOption, 'Second …');
  assert.equal(results.flyoutMissing.CombineOn, false);
  assert.equal(results.flyoutMissing.CanCombine, false);
  assert.equal(results.flyoutMissing.MainOption, 'Cable');
  assert.equal(results.flyoutMissing.Apps[0].CanMove, true);
  assert.equal(results.flyoutMissing.Apps[0].CanSecond, false);
  assert.equal(results.flyoutNoMove.Apps[0].CanMove, false);
  assert.equal(results.flyoutNoMove.Apps[0].CanSecond, false);
  assert.equal(results.flyoutNoMove.Apps[0].Lane, 'second');
});

test('while combining, the flyout offers Cable between the two and shows which apps are kept on it', () => {
  assert.deepEqual(
    [results.flyoutKept.MainOption, results.flyoutKept.CableOption, results.flyoutKept.SecondOption],
    ['Both', 'Cable', 'Wi-Fi'],
  );
  assert.deepEqual(results.flyoutKept.Apps.map((a) => a.Choice), ['cable', 'main', 'second']);
  // Without combining, or with a server that can't keep apps on the cable, there are two options.
  assert.equal(results.flyoutKeptNoCombine.CableOption, null);
  assert.equal(results.flyoutKeptNoCombine.Apps[0].Choice, 'cable');
  assert.equal(results.flyoutCombine.CableOption, null);
});

test('flyout health describes healthy lines, stopped routing, and actual fallback', () => {
  assert.equal(results.flyoutOn.Health, 'Both lines reach the internet');
  assert.equal(results.flyoutOn.HealthTone, 'ok');
  assert.equal(results.flyoutMissing.Health, 'Cable reaches the internet');
  assert.equal(results.flyoutOff.Health, "Routing is off · apps use Windows' connection");
  assert.equal(results.flyoutError.Health, "Routing stopped · apps use Windows' connection");
  assert.equal(results.flyoutStarting.Health, 'Routing is starting…');
  assert.equal(results.flyoutStopping.Health, 'Routing is turning off…');
  assert.equal(results.flyoutSecondDown.Health, 'Wi-Fi stick: no internet · its apps use the cable');
  assert.equal(results.flyoutMainDown.Health, 'Cable: no address · apps use the Wi-Fi stick');
  assert.equal(results.flyoutBothDown.Health, 'Cable: not connected · Wi-Fi stick: no internet');
  assert.equal(results.flyoutNoFallback.Health, 'Wi-Fi stick: no default route');
  assert.equal(results.flyoutMainRecovering.Health, 'Cable is recovering · apps use the Wi-Fi stick');
  assert.equal(results.flyoutSecondRecovering.Health, 'Wi-Fi stick is recovering · its apps use the cable');
  assert.equal(results.flyoutSingleDown.Health, 'Cable: no address');
  assert.equal(results.flyoutMainDown.HealthTone, 'warning');
});

test('flyout line detail tolerates absent ping and counts, and unhealthy lines show their problem', () => {
  assert.equal(results.flyoutOn.Main.Title, 'Cable · 18 ms');
  assert.equal(results.flyoutOn.Second.Title, 'Wi-Fi stick');
  assert.equal(results.flyoutOn.Second.Detail, 'Wi-Fi 2 · Home');
  assert.equal(results.flyoutOld.Main.Speed, 'Not measured');
  assert.equal(results.flyoutOld.RoutingWanted, true);
  assert.equal(results.flyoutMainDown.Main.Healthy, false);
  assert.equal(results.flyoutMainDown.Main.Speed, 'no address');
  assert.equal(results.flyoutMainDown.Main.Lit, 0);
  assert.deepEqual([results.flyoutRateZero.lit, results.flyoutRate1k.lit, results.flyoutRate1m.lit, results.flyoutRate10m.lit], [0, 1, 18, 24]);
});

test('an unreachable flyout has a reconnect message and no stale apps or lines', () => {
  assert.equal(results.flyoutUnavailable.Available, false);
  assert.equal(results.flyoutUnavailable.Message, 'Net Switch isn’t responding.');
  assert.deepEqual(results.flyoutUnavailable.Apps, []);
  assert.equal(results.flyoutUnavailable.Main, null);
  assert.equal(results.flyoutUnavailable.Second, null);
});
