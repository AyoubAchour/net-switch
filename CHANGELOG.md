# Changelog

All notable changes to Net Switch are listed here. Versions follow
[Semantic Versioning](https://semver.org/); before 1.0, minor versions may
change behavior.

## [Unreleased]

- ARM64 PCs now get a native build; an x64 copy on an ARM64 PC moves to it with the next update.
- The tray icon is now a small program of its own instead of a PowerShell
  script compiled at every start: it appears in under a second instead of
  about four, and uses about half the memory (around 45 MB instead of 97 MB).
  Windows sees it as a new icon, so if it shows up under the ^ arrow after
  updating, drag it back onto the taskbar.
- Net Switch now hears about network changes from Windows instead of asking
  every few seconds, through its native helper. That took its steady
  background CPU use from about 0.4 of a core to almost nothing, and the
  scans that sometimes hung for 20 seconds are gone.

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

[Unreleased]: https://github.com/AyoubAchour/net-switch/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/AyoubAchour/net-switch/releases/tag/v0.2.0
[0.1.0]: https://github.com/AyoubAchour/net-switch/releases/tag/v0.1.0
