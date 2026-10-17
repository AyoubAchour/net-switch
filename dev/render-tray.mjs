// Draws the tray's flyout and icon for each made-up state in
// test/tray-states.mjs, so a change to lib/tray.cs can be looked at without a
// running Net Switch:
//
//   node dev/render-tray.mjs [folder]        (dist\tray-flyout by default)
//
// It compiles lib/tray.cs with Windows PowerShell 5.1, as the tray tests do,
// writes <state>.png (the flyout at 200%) and <state>-icon.png (the 16 px
// icon, enlarged 8 times so each pixel shows), and prints each tooltip.
import { execFileSync } from 'node:child_process';
import { mkdirSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { STATES } from '../test/tray-states.mjs';

const ROOT = fileURLToPath(new URL('..', import.meta.url));
const OUT = path.resolve(process.argv[2] ?? path.join(ROOT, 'dist', 'tray-flyout'));
const POWERSHELL = path.join(process.env.SystemRoot ?? 'C:\\Windows', 'System32', 'WindowsPowerShell', 'v1.0', 'powershell.exe');

const RUNNER = String.raw`
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [Text.Encoding]::UTF8
Add-Type -Path $env:NETSWITCH_TRAY_CS -ReferencedAssemblies System.Windows.Forms, System.Drawing, System.Net.Http, System.Web.Extensions
$json = New-Object System.Web.Script.Serialization.JavaScriptSerializer
$states = $json.DeserializeObject($env:NETSWITCH_STATES)
foreach ($name in $states.Keys) {
  $state = $states[$name]
  $flyout = [NetSwitch.FlyoutForm]::Snapshot([NetSwitch.FlyoutModel]::FromState($state), 2)
  $flyout.Save((Join-Path $env:NETSWITCH_OUT "$name.png"), [System.Drawing.Imaging.ImageFormat]::Png)
  $flyout.Dispose()
  $view = [NetSwitch.TrayModel]::FromState($state)
  $icon = [NetSwitch.TrayPainter]::Paint($view, 16)
  $big = New-Object System.Drawing.Bitmap 128, 128
  $g = [System.Drawing.Graphics]::FromImage($big)
  $g.InterpolationMode = [System.Drawing.Drawing2D.InterpolationMode]::NearestNeighbor
  $g.PixelOffsetMode = [System.Drawing.Drawing2D.PixelOffsetMode]::Half
  $g.DrawImage($icon, 0, 0, 128, 128)
  $g.Dispose()
  $icon.Dispose()
  $big.Save((Join-Path $env:NETSWITCH_OUT "$name-icon.png"), [System.Drawing.Imaging.ImageFormat]::Png)
  $big.Dispose()
  "== $name ($name.png)"
  [NetSwitch.TrayModel]::Tooltip($view)
  ''
}
`;

mkdirSync(OUT, { recursive: true });
const output = execFileSync(POWERSHELL, ['-NoProfile', '-NonInteractive', '-EncodedCommand', Buffer.from(RUNNER, 'utf16le').toString('base64')], {
  env: {
    ...process.env,
    NETSWITCH_TRAY_CS: path.join(ROOT, 'lib', 'tray.cs'),
    NETSWITCH_STATES: JSON.stringify(STATES),
    NETSWITCH_OUT: OUT,
  },
  encoding: 'utf8',
  stdio: ['ignore', 'pipe', 'inherit'],
  windowsHide: true,
  timeout: 120_000,
});
console.log(output.trim());
console.log(`\nPictures in ${OUT}`);
