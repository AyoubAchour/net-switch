# Security

Net Switch changes how your PC routes traffic and runs part of itself as
administrator, so security reports are taken seriously.

## Reporting a problem

Please don't open a public issue for a security problem. Use GitHub's private
reporting instead: the **Security** tab of this repository, then
**Report a vulnerability**. I'll reply within a week, and sooner if it's serious.

Only the latest release gets security fixes.

## What runs with which rights

- **The server** (`server.mjs`, run by the bundled Node.js) runs as
  administrator. It needs that to create the virtual network adapter that
  routing goes through, to read which program owns each connection, and to
  change the two Windows settings described below. It listens only on
  `127.0.0.1`.
- **The routing engine** ([sing-box](https://github.com/SagerNet/sing-box)) is
  started by the server, so it also runs as administrator. Before each start,
  Net Switch checks its files against the hashes in `engine/SHA256SUMS.txt`.
  That catches a damaged or swapped file; it is an integrity check, not a
  security boundary, since both live in the same folder.
- **The native helper** (`helper\netswitch-helper.exe`, Net Switch's own
  small program, built from the `helper` folder of this repository) is also
  started by the server and runs as administrator. It reads each adapter's
  byte counters and the list of TCP connections, turns on Windows' byte counts
  for connections that go around routing, and reports them to the server. It
  also watches for adapter, address and route changes and reads the Wi-Fi
  policy. Its `probe` mode can open a TCP connection to a given IPv4 address
  through a given adapter; failover doesn't use it yet. Its `guard` mode
  stops the routing engine if the server ends: it holds handles to both and
  checks the engine's full path and start time, so a reused process id can't
  point it at another program.
- **The window and the tray icon** run as you, not as administrator. The tray
  icon is Net Switch's own small program (`tray\NetSwitchTray.exe`, built from
  `lib\tray.cs` in this repository with the C# compiler that comes with
  Windows). It talks only to the server on `127.0.0.1`. **Open Net Switch**
  opens the window in your browser (or runs `launch.ps1` when Net Switch isn't
  running), and its update offer opens only installer links from this
  project's GitHub releases.

The window and tray talk to the server with a random key made at each start.
It is saved in `%LOCALAPPDATA%\Net Switch\server.json`, readable by your
account. Any program running as you can therefore control Net Switch while it
runs, the same as it could click the window. Net Switch is meant for a
single-user PC; it doesn't try to protect one Windows user from another.

## What it changes on your PC

Only when you press the buttons that offer them:

- the priority (interface metric) of your second connection, so Windows keeps
  using the cable when Net Switch is off;
- the `fMinimizeConnections` policy, so Windows keeps Wi-Fi connected while the
  cable is plugged in.

Before changing either one, it saves how it was in
`%ProgramData%\Net Switch\windows-undo.json`. At each start the server makes
sure that folder is a normal folder (not a link) that only administrators and
SYSTEM can open, and refuses to start otherwise. **Undo** in the window, or
uninstalling, puts the settings back.

Uninstalling leaves your settings and logs in `%LOCALAPPDATA%\Net Switch`;
delete that folder by hand if you want them gone.

## What it sends over the network

No telemetry. Net Switch makes two kinds of requests on its own.

**Update checks.** A minute after it starts, then twice a day, it asks GitHub's
API for this project's latest release
(`api.github.com/repos/AyoubAchour/net-switch/releases/latest`). The request
says which Net Switch version is asking, and GitHub sees your public address,
as with any request. It only reads the answer: Net Switch never downloads or
runs anything by itself. A newer release is offered in the window, and the
installer downloads in your browser like any other file. Turn this off with
**Check for updates** at the bottom of the window.

**Connectivity checks** through each line while routing is on with two
lines: every 30 seconds while the line is healthy, more often after a failure.
Each is an HTTPS request to `1.1.1.1` (Cloudflare), or to `8.8.8.8` (Google)
if that fails (both at once after a failed check). They carry nothing about
you, though like any request they show those companies your public addresses.

## Bug reports and logs

Logs can contain program paths, IP addresses and network names. Look through
them before attaching them to an issue. **Never** post `server.json` or
`engine-config.json`: they contain secret keys.
