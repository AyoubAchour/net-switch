# Net Switch: per-app internet for Windows
<!-- gating probe: stacked docs-only change, do not merge -->

Choose which internet connection each Windows app uses.

![The Net Switch window: a card per line with live speeds, the combine card with each line's share, and a list of apps with their line](docs/images/window.png)

I have two internet connections at home: a cable that is slow but steady, and a
USB Wi-Fi stick on a second router. Windows kept sending everything through the
cable. When something big was downloading, everything else crawled while the
second line sat there doing nothing.

Net Switch lists the apps using your internet, sorted by speed, and lets you
send each one to the line you choose. A line is any connection Windows has: a
cable, built-in Wi-Fi, a USB Wi-Fi adapter, or a phone with USB tethering. Use
two, or as many as you have.

## What it does

- **Pick a line per app.** Put the game download on one line and keep your
  browser and calls on another. You can choose a line for an app before it has
  even started, and the choice stays when the app updates itself.
- **Combine your lines.** New connections from the apps you haven't placed are
  spread across your lines. Downloads that open several connections at once
  (Steam, browsers, speed tests, download managers) can use all of them. **Auto**
  gives each line a share that follows its measured speed; **Manual** lets you
  set the split yourself. Apps that should stay on one line, like calls or a
  picky website, can be kept there.
- **Fail over.** If a line drops, or stays connected but stops reaching the
  internet, its apps move to the next line that works, in the order you set.
  When it comes back, new connections go back to it, and nothing that is
  working gets cut off.
- **Phone data under control.** Mark a line as metered to count what it uses,
  keep it for the apps you choose only, and give it a daily or monthly cap.
  Once the cap is reached, its apps use your other lines until the cap resets.
- **Start with Windows.** Turn it on once and Net Switch starts when you sign
  in, without asking for administrator permission each time.
- **Live traffic meters.** Line speeds come from Windows, per-app speeds from
  the routing engine, so you can see a switch worked instead of guessing.
- **Tray controls.** The tray icon shows your lines at a glance, tells you when
  one goes down or comes back, and a click opens a small panel for the common
  switches.

<img src="docs/images/tray.png" alt="The tray panel: routing and combining toggles, each line's speed, and the busiest apps" width="372">

## Download

Get the installer for your PC from the
[latest release](https://github.com/AyoubAchour/net-switch/releases/latest):

- **Intel or AMD, Windows 10 or 11:** `NetSwitch-Setup-<version>-x64.exe`.
- **ARM64, Windows 11:** `NetSwitch-Setup-<version>-arm64.exe`.

Run it to install Net Switch and its bundled runtime and routing engine.
The ARM64 tray uses .NET Framework 4.8.1, included in Windows 11 22H2 and newer.

The installer isn't code-signed yet, so Windows SmartScreen may warn you about
it. Choose **More info**, then **Run anyway**. If you'd like to check the file
first, each release lists its SHA-256 hashes in `SHA256SUMS.txt`, and you can
verify it was built from this repository by GitHub Actions:

```
gh attestation verify NetSwitch-Setup-<version>-x64.exe -R AyoubAchour/net-switch
gh attestation verify NetSwitch-Setup-<version>-arm64.exe -R AyoubAchour/net-switch
```

## Before you install

- **It needs administrator permission.** It routes traffic through its own
  virtual network adapter and sees which app owns each connection. Windows asks
  each time Net Switch starts, unless you turn on **Start with Windows** in its
  settings. The window and tray icon run as you.
- **One connection still uses one line.** Combining spreads *connections* across
  your lines; it doesn't split a single connection. A big file downloaded over
  one connection gets one line's speed. That would need a bonding server on the
  internet (like Speedify or OpenMPTCProuter), which Net Switch doesn't use.
- **While combining, websites can see different addresses.** Most don't care. If
  one keeps signing you out, put that browser on one line.
- **IPv6 is routed only while every line has it.** Otherwise Net Switch keeps
  apps on IPv4, so a line without IPv6 can still stand in for one with it.
- **Watch your data plan on a phone.** If your other lines drop, their apps
  move to the phone unless you keep it for chosen apps or give it a cap. While
  routing is on with two lines or more, Net Switch checks each line's internet
  with a tiny connection every 15 seconds (about 2 MB a day per line), and a
  bigger test only when a check fails.
- **It's young.** It's been used daily on Windows 11 with an Ethernet cable and
  a USB Wi-Fi adapter. Other setups (Windows 10, VPN software, phone
  tethering, non-English Windows) should work but haven't been tested much.
  [Bug reports](https://github.com/AyoubAchour/net-switch/issues) are welcome.

## First run

1. Open **Net Switch** from the Start menu and accept the administrator prompt.
   The connection Windows uses for the internet becomes your main line.
2. Your other connections show up as **Add a line**. Add the ones you want.
3. In the app list, pick a line for an app to send it there. New connections
   move at once. A download that's already running keeps its line until you
   pause and resume it.
4. Turn on **Combine** if you want the apps you haven't placed to use all your
   lines. Each app then offers **Shared** and every line, so you can keep some
   apps on one.

Click a line to rename it, make it the main line, mark it as metered, keep it
for chosen apps, give it a data cap, or remove it.

Closing the window keeps routing on, and the tray icon brings it back. **Quit
Net Switch** turns routing off, and every app goes back to Windows' normal
connection.

Net Switch may offer two Windows changes, each with its own button: keeping the
main line as the default when Net Switch is off, and keeping Wi-Fi connected
while a cable is plugged in. It saves how things were before changing them, and
**Undo** puts them back.

The [user guide](docs/user-guide.md) explains failover, combining, data caps and
the tray in more detail.

## Updating

When a newer version is out, Net Switch says so in its window (and in the tray
icon's right-click menu). Press **Download**, then run the installer: it closes
Net Switch, updates it in place and keeps your settings, including your lines
from older versions. You can also just download the latest installer from the
[releases page](https://github.com/AyoubAchour/net-switch/releases/latest) and
run it over your current copy.

Net Switch asks GitHub about new versions twice a day; turn that off with
**Check for updates** in its settings, or press **Check now** there to look
right away.

## Uninstalling

Use **Settings → Apps → Installed apps → Net Switch → Uninstall**. It asks
whether to undo the Windows settings Net Switch changed (yes is the default),
and it removes the tasks that start Net Switch with Windows. Your Net Switch
settings stay in `%LOCALAPPDATA%\Net Switch`; delete that folder if you don't
plan to reinstall.

## How it works

Net Switch runs [sing-box](https://github.com/SagerNet/sing-box) as a local
routing engine behind a virtual network adapter. sing-box sees which program
opened each new connection, and Net Switch tells it which line to send that
program's connections through. A small Node.js server keeps the rules up to
date, watches every line, and serves the window as a page on `127.0.0.1`.

Your traffic goes straight out through your own connections; nothing is relayed
through a server of mine, and there's no telemetry. [SECURITY.md](SECURITY.md)
lists what runs as administrator, what Net Switch changes in Windows, and the
only network requests it makes on its own.

## Building from source

See [CONTRIBUTING.md](CONTRIBUTING.md). There are no npm dependencies, and
`node dev/demo-server.mjs` shows the window with sample data, without
administrator rights or a second connection.

## License

Net Switch's code is under the [MIT license](LICENSE). The installer also
includes sing-box (GPL-3.0), Node.js (MIT) and other components under their own
licenses; see [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md). Net Switch isn't
affiliated with the sing-box project.
