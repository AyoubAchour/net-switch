import assert from 'node:assert/strict';
import { test } from 'node:test';
import { appKey } from '../lib/apps.mjs';
import { appPathPattern } from '../lib/engine.mjs';

const paths = [
  [String.raw`C:\Users\Ayoub\AppData\Local\Discord\app-1.0.9164\Discord.exe`, String.raw`c:\users\ayoub\appdata\local\discord\app-*\discord.exe`],
  [String.raw`C:\Users\Ayoub\AppData\Local\Discord\app-1.0.9165\Discord.exe`, String.raw`c:\users\ayoub\appdata\local\discord\app-*\discord.exe`],
  [String.raw`C:\Users\Ayoub\AppData\Local\slack\app-4.40.126\slack.exe`, String.raw`c:\users\ayoub\appdata\local\slack\app-*\slack.exe`],
  [String.raw`C:\Users\Ayoub\AppData\Local\slack\app-4.41.0\slack.exe`, String.raw`c:\users\ayoub\appdata\local\slack\app-*\slack.exe`],
  [String.raw`C:\JetBrains\Toolbox\apps\IDEA-U\ch-0\243.21565.199\bin\idea64.exe`, String.raw`c:\jetbrains\toolbox\apps\idea-u\ch-0\*\bin\idea64.exe`],
  [String.raw`C:\JetBrains\Toolbox\apps\IDEA-U\ch-0\251.23774.435\bin\idea64.exe`, String.raw`c:\jetbrains\toolbox\apps\idea-u\ch-0\*\bin\idea64.exe`],
  [String.raw`C:\Program Files\Browser\Application\131.0.6778.86\browser.exe`, String.raw`c:\program files\browser\application\*\browser.exe`],
  [String.raw`C:\Program Files\Browser\Application\132.0.6834.83\browser.exe`, String.raw`c:\program files\browser\application\*\browser.exe`],
  [String.raw`C:\Tools\v1.2\tool.exe`, String.raw`c:\tools\v*\tool.exe`],
  [String.raw`C:\Tools\V2.10.3\tool.exe`, String.raw`c:\tools\v*\tool.exe`],
  [String.raw`C:\Program Files\WindowsApps\Microsoft.WindowsTerminal_1.21.3231.0_x64__8wekyb3d8bbwe\WindowsTerminal.exe`, String.raw`c:\program files\windowsapps\microsoft.windowsterminal_*_x64__8wekyb3d8bbwe\windowsterminal.exe`],
  [String.raw`C:\Program Files\WindowsApps\Microsoft.WindowsTerminal_1.22.10352.0_x64__8wekyb3d8bbwe\WindowsTerminal.exe`, String.raw`c:\program files\windowsapps\microsoft.windowsterminal_*_x64__8wekyb3d8bbwe\windowsterminal.exe`],
];

const unchanged = [
  String.raw`C:\Program Files\Microsoft Visual Studio\2022\Community\Common7\IDE\devenv.exe`,
  String.raw`C:\Program Files\Microsoft Visual Studio\2019\Community\Common7\IDE\devenv.exe`,
  String.raw`C:\Steam\steamapps\common\Game 2\game.exe`,
  String.raw`C:\Steam\steamapps\common\Game 3\game.exe`,
  String.raw`C:\Tools\1\tool.exe`,
  String.raw`C:\Tools\app-1\tool.exe`,
  String.raw`C:\Tools\v1\tool.exe`,
  String.raw`C:\Tools\1.2-beta\tool.exe`,
  String.raw`C:\Tools\1x2\tool.exe`,
  String.raw`C:\Tools\release-1.2\tool.exe`,
  String.raw`C:\Tools\1.2`,
  String.raw`C:\a (x86)\b+c.exe`,
];

test('only complete version folders normalize; years, app names and files stay literal', () => {
  for (const [file, expected] of paths) assert.equal(appKey(file), expected, file);
  for (const file of unchanged) assert.equal(appKey(file), file.toLowerCase(), file);
});

test('identity agrees with the routing pattern for every pair in the path table', () => {
  const files = [...paths.map(([file]) => file), ...unchanged,
    paths[0][0].replace('app-', 'v'),
    paths[0][0].replace('app-', ''),
    paths[0][0].replace('Discord.exe', 'Update.exe'),
    paths[4][0].replace('ch-0', 'ch-1'),
    paths[10][0].replace('_x64__', '_arm64__'),
    paths[10][0].replace('8wekyb3d8bbwe', 'anotherpublisher'),
    paths[10][0].replace('Microsoft.WindowsTerminal_', 'Microsoft.WindowsTerminalPreview_'),
  ];
  for (const a of files) {
    const pattern = new RegExp(appPathPattern(a).replace('(?i)', ''), 'i');
    for (const b of files.flatMap((file) => [file, file.toUpperCase(), `${file}.bak`, `D:${file.slice(2)}`])) {
      assert.equal(pattern.test(b), appKey(a) === appKey(b), `${a} against ${b}`);
    }
  }
});
