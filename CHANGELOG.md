# Changelog

All notable changes to Net Switch are listed here. Versions follow
[Semantic Versioning](https://semver.org/); before 1.0, minor versions may
change behavior.

## [0.1.0] - 2026-10-14

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
