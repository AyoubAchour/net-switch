import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { after, before, test as nodeTest } from 'node:test';
import { fileURLToPath } from 'node:url';
import { cable, down, line, phone, state, STATES, wifi } from './tray-states.mjs';

// The tray icon's logic is C# (lib/tray.cs), compiled by Windows PowerShell 5.1
// the same way tray.ps1 compiles it. All cases run in one PowerShell call, and
// every flyout case is also drawn, so a state that breaks the drawing fails here.
const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), '..');
const POWERSHELL = path.join(process.env.SystemRoot ?? 'C:\\Windows', 'System32', 'WindowsPowerShell', 'v1.0', 'powershell.exe');
const test = (name, fn) => nodeTest(name, { skip: process.platform !== 'win32' }, fn);

const RUNNER = String.raw`
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
[Console]::OutputEncoding = [Text.Encoding]::UTF8
Add-Type -Path $env:NETSWITCH_TRAY_CS -ReferencedAssemblies System.Windows.Forms, System.Drawing, System.Net.Http, System.Web.Extensions
$json = New-Object System.Web.Script.Serialization.JavaScriptSerializer
$json.MaxJsonLength = 16MB
$results = foreach ($case in $json.DeserializeObject($env:NETSWITCH_CASES)) {
  switch ($case['kind']) {
    'flyout' {
      $view = [NetSwitch.FlyoutModel]::FromState($case['state'])
      [NetSwitch.FlyoutForm]::Snapshot($view, 1).Dispose()
      $view
    }
    'flyoutSize' {
      $picture = [NetSwitch.FlyoutForm]::Snapshot([NetSwitch.FlyoutModel]::FromState($case['state']), 1)
      @{ width = $picture.Width; height = $picture.Height }
      $picture.Dispose()
    }
    'flyoutRate' { @{ lit = [NetSwitch.FlyoutModel]::Lit([double]$case['value']) } }
    'updateOffer' { @{ offer = [NetSwitch.TrayModel]::UpdateOffer($case['state']) } }
    'rate' { @{ text = [NetSwitch.TrayModel]::Rate([double]$case['value']); lit = [NetSwitch.TrayModel]::Lit([double]$case['value']) } }
    'notify' {
      # One reading a second, as the tray polls, of the newest step's events.
      $notifier = New-Object NetSwitch.EventNotifier
      $start = New-Object DateTime 2026, 10, 17, 0, 0, 0, ([DateTimeKind]::Utc)
      $current = $null
      $shown = foreach ($second in 0..$case['until']) {
        foreach ($step in $case['steps']) { if ($step['at'] -eq $second) { $current = $step } }
        if ($current) {
          $reading = New-Object 'System.Collections.Generic.Dictionary[string,object]'
          $reading['events'] = $current['events']
          $notifier.Read([NetSwitch.EventNotifier]::FromState($reading), [bool]$current['enabled'])
        }
        $notice = $notifier.Next($start.AddSeconds($second))
        if ($notice) { @{ at = $second; id = $notice.EventId; title = $notice.Title; text = $notice.Text; warning = $notice.Warning } }
      }
      @{ shown = @($shown) }
    }
    'settings' {
      $missing = [NetSwitch.TraySettings]::Load((Join-Path $case['dir'] 'missing.json'))
      $damaged = [NetSwitch.TraySettings]::Load((Join-Path $case['dir'] 'damaged.json'))
      $saved = New-Object NetSwitch.TraySettings
      $saved.LineNotifications = $false
      $file = Join-Path $case['dir'] 'tray-settings.json'
      $saved.Save($file)
      @{ missing = $missing.LineNotifications; damaged = $damaged.LineNotifications; reloaded = [NetSwitch.TraySettings]::Load($file).LineNotifications; text = [IO.File]::ReadAllText($file).Trim() }
    }
    default {
      $view = switch ($case['kind']) {
        'state' { [NetSwitch.TrayModel]::FromState($case['state']) }
        'unreachable' { [NetSwitch.TrayModel]::Unreachable([bool]$case['running']) }
        'quitting' { [NetSwitch.TrayModel]::Quitting() }
      }
      $bitmap = [NetSwitch.TrayPainter]::Paint($view, 16)
      $pixels = foreach ($point in $case['points']) { '{0:x8}' -f $bitmap.GetPixel($point[0], $point[1]).ToArgb() }
      $bitmap.Dispose()
      @{ tooltip = [NetSwitch.TrayModel]::Tooltip($view); icon = [NetSwitch.TrayModel]::IconSignature($view); pixels = @($pixels) }
    }
  }
}
$json.Serialize(@($results))
`;

const KB = 1024;
// A corner, the panel between the rows, the first and last cells of the first
// row, the first cell of the second row: where the 16 px icon draws two rows.
const TWO_ROWS = [[0, 0], [8, 7], [1, 3], [13, 3], [1, 9]];
// The first cell of each of three thinner rows.
const THREE_ROWS = [[1, 2], [1, 6], [1, 10]];

const cableNow = { ...cable, rate: { down: 6098, up: 6916 } };
const wifiNow = { ...wifi, rate: { down: 937_439, up: 0 } };
const tray = (options, points = TWO_ROWS) => ({ kind: 'state', state: state(options), points });

const event = (id, kind, lineId, text) => ({ id, at: 0, kind, lineId, text });
const e1 = event('e1', 'down', wifi.id, 'Wi-Fi stick is down: it doesn’t reach the internet.');
const e2 = event('e2', 'up', wifi.id, 'Wi-Fi stick is back.');
const e3 = event('e3', 'down', phone.id, 'Phone is down: it isn’t connected.');
const e4 = event('e4', 'down', wifi.id, 'Wi-Fi stick is down: it doesn’t reach the internet.');
const e5 = event('e5', 'up', wifi.id, 'Wi-Fi stick is back.');
const e6 = event('e6', 'down', wifi.id, 'Wi-Fi stick is down: it doesn’t reach the internet.');
const e7 = event('e7', 'up', wifi.id, 'Wi-Fi stick is back.');
const e8 = event('e8', 'down', phone.id, 'Phone is down: it isn’t connected.');
const e9 = event('e9', 'cap-reset', phone.id, 'Phone can be used again: its data cap has reset.');

const settingsDir = mkdtempSync(path.join(os.tmpdir(), 'netswitch-tray-settings-'));
writeFileSync(path.join(settingsDir, 'damaged.json'), '{ not json');

const CASES = {
  routingOn: tray({ lines: [cableNow, wifiNow] }),
  routingOff: tray({ status: 'off', lines: [cableNow, wifiNow] }),
  stopped: tray({ status: 'error', lines: [cableNow, wifiNow] }),
  oneLine: tray({ lines: [cableNow] }),
  secondDown: tray({ lines: [cableNow, down(wifi, 'no internet', cable.id)] }),
  noSpeed: tray({ lines: [{ ...cableNow, rate: null }, wifiNow] }),
  uploadOnly: tray({ lines: [cableNow, line('ph', 'Phone', { rate: { down: 0, up: 2_000_000 } })] }),
  testMode: tray({ mode: 'proxy', lines: [cableNow, wifiNow] }),
  longLabel: tray({
    status: 'stopping',
    lines: [cableNow, line('rt', 'Realtek USB GbE Family Controller #2', { rate: { down: 123_456_789, up: 123_456_789 } })],
  }),
  threeLines: tray({ lines: [cableNow, wifiNow, { ...phone, rate: { down: 120 * KB, up: 8 * KB } }] }, THREE_ROWS),
  checking: tray({ lines: [cableNow, down(wifi, 'checking', cable.id)] }),
  exhausted: tray({ lines: [cableNow, wifiNow, { ...phone, exhausted: true, target: cable.id }] }),
  sixLines: tray({ lines: [1, 2, 3, 4, 5, 6].map((n) => line(`c${n}`, `Connection ${n}`)) }),
  fourLinesTip: tray({ lines: STATES.fourLines.lines }),
  stuck: { kind: 'unreachable', running: true, points: TWO_ROWS },
  gone: { kind: 'unreachable', running: false, points: TWO_ROWS },
  quitting: { kind: 'quitting', points: TWO_ROWS },
  rate0: { kind: 'rate', value: 0 },
  rateTiny: { kind: 'rate', value: 1000 },
  rate1k: { kind: 'rate', value: 1024 },
  rateTop: { kind: 'rate', value: 1_048_575 },
  rate1m: { kind: 'rate', value: 1_048_576 },
  rate10m: { kind: 'rate', value: 10 * 1_048_576 },
  ...Object.fromEntries(Object.entries(STATES).map(([name, value]) => [`flyout_${name}`, { kind: 'flyout', state: value }])),
  flyoutUnavailable: { kind: 'flyout', state: null },
  sizeTwo: { kind: 'flyoutSize', state: STATES.twoLines },
  sizeFour: { kind: 'flyoutSize', state: STATES.fourLines },
  sizeDown: { kind: 'flyoutSize', state: STATES.lineDown },
  flyoutRateZero: { kind: 'flyoutRate', value: 0 },
  flyoutRate1k: { kind: 'flyoutRate', value: 1024 },
  flyoutRate1m: { kind: 'flyoutRate', value: 1024 * 1024 },
  flyoutRate10m: { kind: 'flyoutRate', value: 10 * 1024 * 1024 },
  updateOffered: {
    kind: 'updateOffer',
    state: { update: { version: '0.3.0', installer: 'https://github.com/AyoubAchour/net-switch/releases/download/v0.3.0/NetSwitch-Setup-0.3.0-x64.exe' } },
  },
  updateElsewhere: { kind: 'updateOffer', state: { update: { version: '0.3.0', installer: 'https://example.com/setup.exe' } } },
  updateNone: { kind: 'updateOffer', state: { update: null } },
  notify: {
    kind: 'notify',
    until: 80,
    steps: [
      // Already there when the tray starts: old news.
      { at: 0, enabled: true, events: [e1, e2] },
      { at: 5, enabled: true, events: [e1, e2, e3] },
      // The Wi-Fi stick, a second after the phone: four seconds apart on screen.
      { at: 6, enabled: true, events: [e1, e2, e3, e4] },
      // Then it flaps: only the newest shows, once its 30 seconds are up.
      { at: 12, enabled: true, events: [e1, e2, e3, e4, e5] },
      { at: 14, enabled: true, events: [e1, e2, e3, e4, e5, e6] },
      { at: 16, enabled: true, events: [e1, e2, e3, e4, e5, e6, e7] },
      // Turned off: this one is never shown, not even after turning back on.
      { at: 50, enabled: false, events: [e1, e2, e3, e4, e5, e6, e7, e8] },
      { at: 60, enabled: true, events: [e1, e2, e3, e4, e5, e6, e7, e8] },
      { at: 70, enabled: true, events: [e1, e2, e3, e4, e5, e6, e7, e8, e9] },
    ],
  },
  settings: { kind: 'settings', dir: settingsDir },
};

const AMBER = 'fff0b23e';
const CYAN = 'ff4cc3e8';
const VIOLET = 'ffb394ff';
const GRAY = 'ffa8adb3';
const PANEL = 'ff141619';
const CLEAR = '00000000';

let results;

before(() => {
  if (process.platform !== 'win32') return;
  const encoded = Buffer.from(RUNNER, 'utf16le').toString('base64');
  let output;
  try {
    output = execFileSync(POWERSHELL, ['-NoProfile', '-NonInteractive', '-OutputFormat', 'Text', '-EncodedCommand', encoded], {
      env: { ...process.env, NETSWITCH_TRAY_CS: path.join(ROOT, 'lib', 'tray.cs'), NETSWITCH_CASES: JSON.stringify(Object.values(CASES)) },
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'pipe'],
      windowsHide: true,
      timeout: 90_000,
    });
  } catch (error) {
    // Keep the compiler's file and line, without burying it under the encoded runner.
    throw new Error(`Tray compilation or model checks failed:\n${error.stderr || error.message}`);
  }
  const list = JSON.parse(output.trim());
  results = Object.fromEntries(Object.keys(CASES).map((name, index) => [name, list[index]]));
});

after(() => rmSync(settingsDir, { recursive: true, force: true }));

// ------------------------------------------------------------ icon and tooltip

test('the tooltip names the routing state and each line with the window’s speed wording', () => {
  assert.equal(
    results.routingOn.tooltip,
    'Net Switch: routing is on\nCable: ↓ 6 KB/s  ↑ 7 KB/s\nWi-Fi stick: ↓ 915 KB/s  ↑ 0 KB/s',
  );
  assert.equal(results.oneLine.tooltip, 'Net Switch: routing is on\nCable: ↓ 6 KB/s  ↑ 7 KB/s');
  assert.match(results.routingOff.tooltip, /^Net Switch: routing is off\n/);
  assert.match(results.stopped.tooltip, /^Net Switch: routing stopped\n/);
  assert.match(results.testMode.tooltip, /^Net Switch: routing is on \(test mode\)\n/);
});

test('a line with a problem says it in the window’s words instead of showing a speed', () => {
  assert.match(results.secondDown.tooltip, /\nWi-Fi stick: no internet$/);
  assert.match(results.checking.tooltip, /\nWi-Fi stick: checking…$/);
  assert.match(results.exhausted.tooltip, /\nPhone: cap reached$/);
  assert.match(results.noSpeed.tooltip, /\nCable: speed not available\n/);
});

test('with many lines the tooltip gives each its download only, then counts the ones that don’t fit', () => {
  assert.equal(
    results.fourLinesTip.tooltip,
    'Net Switch: routing is on\nCable: ↓ 38 KB/s\nWi-Fi stick: ↓ 915 KB/s\nPhone: ↓ 120 KB/s\nWi-Fi stick 2: ↓ 300 KB/s',
  );
  assert.equal(
    results.sixLines.tooltip,
    'Net Switch: routing is on\nConnection 1: ↓ 38 KB/s\nConnection 2: ↓ 38 KB/s\nConnection 3: ↓ 38 KB/s\n+3 more lines',
  );
});

test('when Net Switch can’t be reached, the tooltip says what happened and what a click does', () => {
  assert.equal(results.stuck.tooltip, 'Net Switch isn’t responding\nClick for Open Net Switch.');
  assert.equal(results.gone.tooltip, 'Net Switch isn’t running\nClick for Open Net Switch.');
  assert.equal(results.quitting.tooltip, 'Net Switch is quitting…');
});

test('long labels and big speeds still fit the 127 characters Windows allows', () => {
  for (const name of ['longLabel', 'sixLines', 'fourLinesTip']) assert.ok(results[name].tooltip.length <= 127, `${name}: ${results[name].tooltip.length} characters`);
  assert.match(results.longLabel.tooltip, /^Net Switch: turning off routing…\n/);
  assert.match(results.longLabel.tooltip, /\nRealtek USB GbE F…: ↓ 117\.7 MB\/s {2}↑ 117\.7 MB\/s$/);
});

test('speeds read like the window and light cells on its scale', () => {
  assert.deepEqual(results.rate0, { text: '0 KB/s', lit: 0 });
  assert.deepEqual(results.rateTiny, { text: '<1 KB/s', lit: 1 });
  assert.deepEqual(results.rate1k, { text: '1 KB/s', lit: 1 });
  assert.equal(results.rateTop.text, '1024 KB/s');
  assert.equal(results.rate1m.text, '1.0 MB/s');
  assert.deepEqual(results.rate10m, { text: '10.0 MB/s', lit: 5 });
});

test('the icon has a row per line, lit for its download and upload together, three at most', () => {
  // 13 KB/s on the cable lights one cell, 915 KB/s on the Wi-Fi stick four.
  assert.equal(results.routingOn.icon, 'on|True1|True4');
  // Upload alone still lights the row.
  assert.equal(results.uploadOnly.icon, 'on|True1|True4');
  assert.equal(results.noSpeed.icon, 'on|True0|True4');
  // One line: the second row stays, faint.
  assert.equal(results.oneLine.icon, 'on|True1|False0');
  // A line that is down is faint too.
  assert.equal(results.secondDown.icon, 'on|True1|False0');
  assert.equal(results.threeLines.icon, 'on|True1|True4|True3');
  assert.equal(results.sixLines.icon.split('|').length, 4);
  assert.equal(results.stuck.icon, 'off|False0|False0');
});

test('the icon keeps the line colors only while routing is on, on the dark panel with clear corners', () => {
  const [corner, panel, firstCable, lastCable, firstSecond] = results.routingOn.pixels;
  assert.equal(corner, CLEAR);
  assert.equal(panel, PANEL);
  assert.equal(firstCable, AMBER);
  // One lit cell: the last cable cell is the dim, unlit kind.
  assert.notEqual(lastCable, AMBER);
  assert.equal(firstSecond, CYAN);
  assert.equal(results.routingOff.pixels[2], GRAY);
  // A third line gets the window's third color, in a third, thinner row.
  assert.deepEqual(results.threeLines.pixels, [AMBER, CYAN, VIOLET]);
});

// ------------------------------------------------------------ flyout

const flyout = (name) => results[`flyout_${name}`];

test('the flyout shows each line with its color, health and speed, and Main only beside other lines', () => {
  const one = flyout('oneLine');
  assert.equal(one.Lines.length, 1);
  assert.equal(one.Lines[0].Main, false);
  assert.equal(one.Lines[0].Detail, 'Ethernet · 18 ms');
  assert.equal(one.Lines[0].Speed, '38 KB/s');
  assert.equal(one.Health, 'Cable reaches the internet');

  const two = flyout('twoLines');
  assert.equal(two.Status, 'Routing on · 953 KB/s');
  assert.equal(two.Tone, 'ok');
  assert.deepEqual(two.Lines.map((item) => [item.Name, item.Color, item.Main]), [['Cable', 0, true], ['Wi-Fi stick', 1, false]]);
  assert.equal(two.Lines[1].Detail, 'Wi-Fi 2 · Home · 31 ms');
  assert.equal(two.Lines[1].Lit, 18);
  assert.equal(two.Health, 'Both lines reach the internet');
  assert.equal(two.HealthTone, 'ok');
});

test('the flyout shows three lines, then "+N more", and data use on a capped line', () => {
  const four = flyout('fourLines');
  assert.equal(four.Lines.length, 3);
  assert.equal(four.MoreLines, 1);
  assert.equal(four.Lines[2].Metered, true);
  assert.equal(four.Lines[2].Detail, '6.2 GB of 10 GB · 54 ms');
  assert.match(four.Lines[2].Tip, /6\.2 GB of 10 GB this month/);
  assert.equal(four.Health, 'All 4 lines reach the internet');
  assert.equal(four.CombineName, 'Combine lines');
  assert.equal(results.sizeFour.height > results.sizeTwo.height, true);
  assert.equal(results.sizeTwo.width, 372);
});

test('a line that is down says why in the window’s words, and where its apps went', () => {
  const lineDown = flyout('lineDown');
  const wifiRow = lineDown.Lines[1];
  assert.equal(wifiRow.Healthy, false);
  assert.equal(wifiRow.Health, 'No internet');
  assert.equal(wifiRow.Tone, 'warn');
  assert.equal(wifiRow.Lit, 0);
  assert.equal(wifiRow.Detail, 'Wi-Fi 2 · Home');
  assert.equal(wifiRow.Note, 'Its apps use the Cable until it’s back');
  assert.equal(lineDown.Health, 'Wi-Fi stick: no internet · its apps use the Cable');
  assert.equal(lineDown.HealthTone, 'warning');
  // The header dot warns too, like the window's top bar.
  assert.equal(lineDown.Tone, 'warning');
  // The note takes the meter's place and is a little taller.
  assert.equal(results.sizeDown.height, results.sizeTwo.height + 8);

  const mainDown = flyout('mainDown');
  assert.equal(mainDown.Lines[0].Health, 'No address');
  assert.equal(mainDown.Lines[0].Tone, 'down');
  assert.equal(mainDown.Health, 'Cable: no address · apps use the Wi-Fi stick');

  const checking = flyout('checking');
  assert.equal(checking.Lines[1].Health, 'Checking…');
  assert.equal(checking.Lines[1].Tone, 'warn');
  assert.equal(checking.Health, 'Wi-Fi stick: checking · its apps use the Cable');
});

test('a line over its data cap says so, sends its apps elsewhere, and leaves sharing', () => {
  const capped = flyout('capped');
  const phoneRow = capped.Lines[2];
  assert.equal(phoneRow.Health, 'Cap reached');
  assert.equal(phoneRow.Detail, '10.3 GB of 10 GB');
  assert.equal(phoneRow.Note, 'Its apps use the Cable until the cap resets');
  assert.equal(capped.Health, 'Phone: cap reached · its apps use the Cable');
  assert.deepEqual(capped.SharingColors, [0, 1]);
  assert.equal(capped.CanCombine, true);
});

test('app choices match the window: every line, Shared first while combining, the main line sending null otherwise', () => {
  const two = flyout('twoLines');
  assert.deepEqual(two.Options.map((option) => [option.Value, option.Send, option.Label]), [[cable.id, null, 'Cable'], [wifi.id, wifi.id, 'Wi-Fi stick']]);
  assert.equal(two.CompactChoice, true);
  // An app with no choice of its own shows the main line chosen.
  assert.deepEqual(two.Apps.map((app) => [app.Name, app.Choice]), [['Steam', cable.id], ['Firefox', wifi.id], ['Discord', cable.id]]);

  const combining = flyout('combining');
  assert.equal(combining.CombineOn, true);
  assert.equal(combining.CombineDetail, 'Combining');
  assert.deepEqual(combining.Options.map((option) => [option.Value, option.Send, option.Shared]), [[null, null, true], [cable.id, cable.id, false], [wifi.id, wifi.id, false]]);
  assert.equal(combining.CompactChoice, true);
  assert.deepEqual(combining.Apps.map((app) => app.Choice), [null, wifi.id, cable.id]);
  assert.deepEqual(combining.SharingColors, [0, 1]);

  // Four lines are more than the flyout's compact control holds: Change opens the window.
  const four = flyout('fourLines');
  assert.equal(four.Options.length, 4);
  assert.equal(four.CompactChoice, false);
  assert.equal(four.Apps.find((app) => app.Name === 'Spotify').Choice, phone.id);

  // One line: nothing to choose, nothing to combine.
  const one = flyout('oneLine');
  assert.equal(one.Options.length, 1);
  assert.equal(one.CanCombine, false);
  assert.equal(one.CombineDetail, 'Add a second line');
});

test('long names are shortened for the controls, not in the line rows’ tooltips', () => {
  const long = flyout('longNames');
  assert.deepEqual(long.Options.map((option) => option.Label), ['Fibre from…', 'Wi-Fi stick…', 'Ayoub’s pho…']);
  assert.equal(long.Lines[0].Name, 'Fibre from the basement router');
  assert.equal(long.Lines[2].Detail, '2.5 GB of 10 GB · 18 ms');
  assert.match(long.Lines[2].Tip, /2\.5 GB of 10 GB today/);
  assert.equal(long.Apps[0].Name, 'Microsoft Edge WebView2 helper for the company sign-in page');
});

test('with routing off the flyout says so, and lines read Online', () => {
  const off = flyout('routingOff');
  assert.equal(off.Status, 'Routing off · 953 KB/s');
  assert.equal(off.Tone, 'dim');
  assert.equal(off.RoutingWanted, false);
  assert.equal(off.Health, "Routing is off · apps use Windows' connection");
  assert.equal(off.Lines[0].Detail, 'Ethernet · Online');
  assert.equal(off.Lines[0].Note, null);
});

test('an unreachable flyout has a reconnect message and no stale apps or lines', () => {
  assert.equal(results.flyoutUnavailable.Available, false);
  assert.equal(results.flyoutUnavailable.Message, 'Net Switch isn’t responding.');
  assert.deepEqual(results.flyoutUnavailable.Apps, []);
  assert.deepEqual(results.flyoutUnavailable.Lines, []);
});

test('flyout meters light on the window’s scale', () => {
  assert.deepEqual([results.flyoutRateZero.lit, results.flyoutRate1k.lit, results.flyoutRate1m.lit, results.flyoutRate10m.lit], [0, 1, 18, 24]);
});

test('the tray offers an update only with a link to this project’s releases', () => {
  assert.deepEqual(results.updateOffered.offer, [
    '0.3.0',
    'https://github.com/AyoubAchour/net-switch/releases/download/v0.3.0/NetSwitch-Setup-0.3.0-x64.exe',
  ]);
  assert.equal(results.updateElsewhere.offer, null);
  assert.equal(results.updateNone.offer, null);
});

// ------------------------------------------------------------ notifications

test('each line event is shown once, old ones never, at most one per line per 30 seconds, the newest winning', () => {
  assert.deepEqual(
    results.notify.shown.map(({ at, id, title }) => [at, id, title]),
    [
      [5, 'e3', 'Line down'],
      [9, 'e4', 'Line down'],
      [39, 'e7', 'Line back'],
      [70, 'e9', 'Data cap reset'],
    ],
  );
  const [phoneDown, , wifiBack, capReset] = results.notify.shown;
  assert.equal(phoneDown.text, 'Phone is down: it isn’t connected.');
  assert.equal(phoneDown.warning, true);
  assert.equal(wifiBack.warning, false);
  assert.equal(capReset.warning, false);
});

test('the notifications switch is kept in tray-settings.json, and a missing or damaged file means on', () => {
  assert.equal(results.settings.missing, true);
  assert.equal(results.settings.damaged, true);
  assert.equal(results.settings.reloaded, false);
  assert.equal(results.settings.text, '{"lineNotifications":false}');
});
