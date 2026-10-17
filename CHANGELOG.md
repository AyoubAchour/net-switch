# Changelog

All notable changes to Net Switch are listed here. Versions follow
[Semantic Versioning](https://semver.org/); before 1.0, minor versions may
change behavior.

## [Unreleased]

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

[0.1.0]: https://github.com/AyoubAchour/net-switch/releases/tag/v0.1.0
