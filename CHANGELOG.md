# Changelog

All notable changes to Net Switch are listed here. Versions follow
[Semantic Versioning](https://semver.org/); before 1.0, minor versions may
change behavior.

## [Unreleased]

## [0.3.1] - 2026-10-18

To update, use the update offer in Net Switch or download the installer below
and run it: `x64` for Intel and AMD PCs, `arm64` for ARM64 PCs on Windows 11.

- **No console window at sign-in.** With **Start with Windows** on, 0.3.0
  showed a black window for the Net Switch service after you signed in, and
  closing it turned Net Switch off. The service now starts without a window.
  Updating fixes an existing startup setting by itself; there's nothing to
  turn off and on again.
- **Check now.** Settings has a button to look for a newer version right away,
  with a download button when one is out. It works even with the automatic
  checks turned off.

## [0.3.0] - 2026-10-17

To update, use the update offer in Net Switch or download the installer below
and run it: `x64` for Intel and AMD PCs, `arm64` for ARM64 PCs on Windows 11.
It updates Net Switch in place and keeps your settings.

- **Any number of lines, and any adapter as the main one.** A line can be a
  cable, built-in Wi-Fi, a USB Wi-Fi adapter or a tethered phone, and the
  main line no longer has to be a cable. Add, rename, reorder and remove lines
  in the window. Your cable and second connection from 0.2.0 become your first
  two lines, and every app keeps its line.
- **Combining by speed or by hand.** **Auto** gives each line a share of new
  connections that follows its measured speed; **Manual** lets you set the
  split with sliders.
- **Gentle failback.** When a line comes back, new connections go back to it,
  and nothing that is working gets cut off. Connections that moved while it was
  down stay until they end, and **Reconnect** moves an app's back at once. A
  line whose address comes back now has to pass an internet test before it's
  trusted again, and a line that is busy uploading no longer counts as dead
  when it misses a test.
- **Phone data control.** Mark a line as metered to count what it uses, keep it
  for the apps you choose, and give it a daily or monthly cap (from the day
  your plan renews). Once the cap is reached, its apps use your other lines
  until it starts over.
- **Add an app** chooses a line for an app from the Start menu before it has
  ever run, and an app's line now stays when it updates itself into a new
  version folder (Discord, Slack, JetBrains IDEs, Store apps).
- **Start with Windows**, in the window's new **Settings**, starts Net Switch
  when you sign in, and stops the administrator prompt each time it starts.
  **Check for updates** moved there too, along with the test sites for the
  line checks.
- IPv6 is now routed while every line has it; otherwise apps keep using IPv4
  as before.
- Line checks are lighter: a tiny connection every 15 seconds, and a full
  HTTPS test only when that fails.
- ARM64 PCs (Windows 11) now get a native build. An x64 copy running on an
  ARM64 PC is offered it at its next update.
- The tray icon is now a small program of its own instead of a PowerShell
  script compiled at every start: it appears in under a second instead of
  about four, and uses about half the memory (around 45 MB instead of 97 MB).
  Windows sees it as a new icon, so if it shows up under the ^ arrow after
  updating, drag it back onto the taskbar.
- Net Switch now hears about network changes from Windows instead of asking
  every few seconds, through its native helper. That took its steady
  background CPU use from about 0.4 of a core to almost nothing, and the
  scans that sometimes hung for 20 seconds are gone.
- The tray shows any number of lines: a row of the icon for each of the first
  three, and in its panel each line's speed, health, Main and Metered marks,
  and where a down line's apps went. Apps get a line choice right in the
  panel when there are up to three choices, and a **Change** link otherwise.
- Line notifications: Windows tells you when a line goes down, comes back,
  uses up its data cap or can be used again. A flapping line notifies at most
  every 30 seconds. Turn them off with **Show line notifications** in the
  tray icon's right-click menu.

## [0.2.0] - 2026-10-17

To update from 0.1.0, download the installer below and run it: it updates
Net Switch in place and keeps your settings. From this version on, Net Switch
tells you itself when a newer one is out.

- While combining, an app can be kept on the cable: each app now offers
  **Both lines**, **Cable** and the second connection. Useful for calls, games
  and websites that sign you out when your address changes. If the cable drops,
  those apps still move to the second connection until it's back.
- Fewer false failovers. A line that was busy with a download could miss its
  internet test and get marked as down for a few seconds, which moved apps and
  then cut their new connections. Now a failed test doesn't count while
  internet traffic is still arriving through that line, the test waits up to
  10 seconds instead of 5, and after a failed test both test sites are asked
  at once.
- Update notice: Net Switch checks GitHub twice a day for a newer release and
  offers it in the window and the tray menu. The installer downloads in your
  browser and updates Net Switch in place; nothing is installed by itself.
  Turn the checks off with **Check for updates** at the bottom of the window.
- The window shows which version you're running.
- The faintest text is a little brighter, so it's readable for everyone
  (WCAG AA contrast).
- The line speeds and the check for connections that go around routing now
  come from a small native helper instead of two PowerShell processes running
  in the background. They used over 200 MB of memory and a steady bit of CPU;
  the helper uses under 20 MB and almost no CPU.

## [0.1.0] - 2026-10-15

First public release.

- Choose, per app, whether it uses the cable or a second connection (a USB
  Wi-Fi adapter or a phone with USB tethering).
- Combine both lines: new connections from apps on the cable are spread across
  both lines, so downloads and pages that open several connections get both
  speeds. A single connection still uses one line.
- Failover both ways: apps on the second connection use the cable while it is
  down, and everything else uses the second connection while the cable is down.
  Each line's internet is tested every 30 seconds, so a line that is connected
  but reaches nothing (a phone with mobile data off) counts as down.
- Routing restarts by itself after a crash or a failed start, and Turn off
  always wins.
- Tray icon with a quick panel: routing and combining toggles, both lines'
  speeds, and the busiest apps.
- Windows installer that bundles Node.js and sing-box, and offers to undo
  Net Switch's Windows setting changes when you uninstall.

[Unreleased]: https://github.com/AyoubAchour/net-switch/compare/v0.3.1...HEAD
[0.3.1]: https://github.com/AyoubAchour/net-switch/releases/tag/v0.3.1
[0.3.0]: https://github.com/AyoubAchour/net-switch/releases/tag/v0.3.0
[0.2.0]: https://github.com/AyoubAchour/net-switch/releases/tag/v0.2.0
[0.1.0]: https://github.com/AyoubAchour/net-switch/releases/tag/v0.1.0
