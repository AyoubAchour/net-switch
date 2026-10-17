# Net Switch user guide

The README covers installing. This page explains what Net Switch does in each
situation, for when you want to know why an app ended up on a line.

- [Starting and quitting](#starting-and-quitting)
- [The window](#the-window)
- [Moving an app to the other line](#moving-an-app-to-the-other-line)
- [Combining both lines](#combining-both-lines)
- [When a line drops](#when-a-line-drops)
- [The tray icon](#the-tray-icon)
- [Windows settings Net Switch can change](#windows-settings-net-switch-can-change)
- [Where Net Switch keeps its files](#where-net-switch-keeps-its-files)
- [Limitations](#limitations)
- [Troubleshooting](#troubleshooting)

## Starting and quitting

Open **Net Switch** from the Start menu. Windows asks for administrator
permission each time Net Switch starts; that is what lets it move app traffic.
Routing turns on by itself.

Closing the window keeps routing on, and the icon stays in the taskbar corner.
To get the window back, open Net Switch again from the Start menu, or click the
icon and press **See all** in its panel.

**Quit Net Switch** (bottom right of the window, or in the icon's right-click
menu) turns routing off and stops Net Switch. Every app then uses Windows'
normal connection again. The window only says it has closed once routing has
really stopped.

## The window

The top shows your two lines with their real speeds, read from Windows, so they
include everything on that line. Each line also shows:

- its health: the round trip of its last internet test, **Online** before the
  first test (or while routing is off), or what's wrong ("No internet",
  "No address");
- how many routed connections it is carrying right now.

The list below shows each app that is using the internet, busiest first, with
its speed and two keys for its line.

"App" means one program file: all of Chrome, not one tab. Windows background
services share one program, so they show as one row. You can move that row to
the other line, but **Reconnect** isn't offered for it, because closing its
connections would interrupt Windows itself.

## Moving an app to the other line

Press the second key on an app's row to move it to the second connection, and
the first key to move it back.

New connections move straight away. A connection that is already open stays
where it is. A download that is running keeps using its old line until it's
paused and resumed in that app. The row says what's left behind, and its meter
changes color once the traffic has really moved.

**Reconnect** (offered in that note) closes the app's connections that aren't
on its chosen line, so the app opens new ones there. It tells you how many
connections it will interrupt and asks first. A running connection can't be
moved, only replaced, so some apps stop and need you to press resume. Try it on
a small download first.

Downloads that were already running when routing started also show up, with a
note to pause and resume them.

## Combining both lines

**Combine both lines** spreads new connections from every app you haven't
moved across both lines, about half each. Anything that opens several
connections at once gets both speeds: speed tests, Steam, browsers loading a
page, download managers that download in parts.

A single connection still uses one line. A large file downloaded over one
connection, which many installers and update tools do, gets one line's speed.
To use both lines for one big file, download it with a tool that splits it into
parts, such as `aria2c -x 8 <url>`.

Combining is not bonding. Bonding a single connection across two lines needs a
server on the internet to put the pieces back together (Speedify and
OpenMPTCProuter work that way). Net Switch doesn't relay your traffic through
a server like that; each connection goes straight out through one of your
lines.

While combining, each app has three keys:

- **Both lines**: its new connections are spread over both lines. This is
  where every app starts.
- **Cable**: it stays on the cable, and combining leaves it alone.
- The second connection's key: it uses only the second connection, as without
  combining.

While combining, websites can see your two lines' different public addresses.
If a site keeps signing you out or a download fails, set that browser or app
to **Cable**, or stop combining. Calls and games are often happier on one line
too.

**Cable** still follows failover: if the cable drops, the app uses the second
connection until the cable is back. Net Switch remembers the choice when you
stop combining, and the app goes back to the cable alone when you combine
again.

## When a line drops

- If the second connection drops, its apps use the cable until it's back.
- If the cable drops, every other app uses the second connection until the cable
  is back, as long as the second connection works.
- If both are down, apps stay on their own lines, and whichever line comes
  back first takes over as above.

A line counts as down when its address or default route is missing two checks
in a row, so one bad reading from Windows doesn't move anything.

While routing is on with two lines, Net Switch also tests each line's internet
through that line: every 30 seconds while it's healthy, and every 5 seconds
after a failed test. A line that is connected but reaches nothing (a phone with
mobile data off, a router whose own internet is down) counts as down after
three failed tests in a row, and as back after two passes.

A line that's busy with a big download can be too slow to answer a test in
time. A failed test doesn't count while internet traffic is still arriving
through that line: the line is busy, not dead.

Each test is a small HTTPS request to `1.1.1.1` (Cloudflare), or to `8.8.8.8`
(Google) when that fails. After a failed test, the next ones ask both at once,
so a verdict comes sooner. By my estimate that's about 6 KB per test, roughly
17 MB a day for a healthy line, and more while a line keeps failing. **Keep
that in mind on a metered phone connection.** The tests use IP addresses, so a
test never depends on looking up a name through the other line.

When a line comes back, new connections return to it, and connections that had
moved to the other line in the meantime are closed so their apps open new ones
where they belong. A download caught in that moment may need you to press
resume. The window says how many connections were closed.

If routing stops by itself or can't start, Net Switch starts it again after 5
seconds, then 15, 30, and every minute after that. **Turn off** always wins:
nothing restarts routing you turned off.

If Windows renames your cable adapter (after a driver update, or a USB adapter
in another port), Net Switch follows it. A second connection that is missing
may just be unplugged, so it is kept until it comes back.

## The tray icon

The icon shows two rows of cells: the cable on top (amber) and the second
connection below (cyan). More lit cells mean more traffic on that line. The
cells turn gray while routing is off.

- **Point at it** to see both lines' speeds.
- **Click it** for a small panel:
  - **Routing** and **Both lines** toggles;
  - both lines' speeds;
  - the three busiest apps with their line keys;
  - a health line, and **Quit**.

  Click again, press Esc or click elsewhere to close it. The square button at
  the top and **See all** open the full window.
- **Right-click it** for **Open Net Switch** and **Quit Net Switch**.

If the icon first appears under the ^ arrow, drag it onto the taskbar once.

## Windows settings Net Switch can change

Net Switch may offer two changes, each with its own button:

- **Make the cable the default.** Gives your second connection a lower priority,
  so Windows keeps using the cable while Net Switch is off.
- **Keep both connected.** Sets a Windows policy so Wi-Fi stays connected while
  the cable is plugged in. Without it, Windows may drop the Wi-Fi adapter.

Before changing anything, Net Switch saves how it was. **Undo** in the window
puts it back. So does uninstalling, which asks first (see
[Where Net Switch keeps its files](#where-net-switch-keeps-its-files)). If an adapter isn't
connected when you undo, Net Switch keeps that part of the record and tells
you to connect it and press Undo again.

## Where Net Switch keeps its files

An installed copy uses three places:

| Folder | What's in it |
| --- | --- |
| `C:\Program Files\Net Switch` | The program, with its own Node.js and sing-box |
| `%LOCALAPPDATA%\Net Switch` | Your settings (`settings.json` and a backup), `server.log`, `tray.log`, `launch.log` |
| `%ProgramData%\Net Switch` | The Windows undo record and the engine's files and log (administrators only) |

If `settings.json` is damaged, Net Switch keeps a copy as
`settings.json.corrupt-…` and starts from the backup, or from the defaults if
the backup is damaged too. A single setting with an impossible value goes back
to its default on its own. Either way, `server.log` says what happened.

Logs stay small. `server.log` and the engine log start over in a `.1` file past
2 MB and 5 MB, `launch.log` past 1 MB, and `tray.log` is cleared at startup
once it passes 512 KB.

Uninstalling removes the program folder. It removes `%ProgramData%\Net Switch`
only once the Windows changes are undone, or if you tell it to drop the undo
record; if undoing fails, the record stays so a reinstall can try again. Your
settings and logs in `%LOCALAPPDATA%\Net Switch` always stay, so a reinstall
picks up where you left off. Delete that folder if you don't want them.

## Limitations

- Routing is IPv4 only. While it's on, apps are told IPv6 is unavailable, which
  makes them use IPv4 straight away instead of waiting on IPv6.
- One connection always uses one line (see [Combining](#combining-both-lines)).
- Traffic to devices on your own networks (router pages, printers, other PCs)
  isn't routed or listed per app. The line meters include it.
- Speeds are sampled once a second, so very short connections are undercounted.
- Net Switch is built and tested on Windows 11 x64 with one Ethernet adapter and
  one USB Wi-Fi adapter. Other setups (Windows 10, VPN software, phone
  tethering, non-English Windows) should work but haven't been tested much
  yet. Reports are welcome.

## Troubleshooting

- **The window says routing couldn't start.** Press **Details** in the message.
  Net Switch also retries by itself. The full log is `server.log` in
  `%LOCALAPPDATA%\Net Switch`.
- **Nothing opens when I start Net Switch.** Check `launch.log` in
  `%LOCALAPPDATA%\Net Switch`.
- **The internet stopped working and Net Switch won't open.** Run this in a
  PowerShell window opened as administrator. It stops only Net Switch's own
  processes, not other Node.js programs:

  ```powershell
  powershell -NoProfile -ExecutionPolicy Bypass -File "C:\Program Files\Net Switch\tools\stop.ps1" -AppDir "C:\Program Files\Net Switch"
  ```

  Windows routing goes back to normal as soon as the routing engine stops.
- **A website keeps signing me out.** Stop combining, or move that browser to
  the second connection.
