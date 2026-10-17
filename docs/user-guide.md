# Net Switch user guide

The README covers installing. This page explains what Net Switch does in each
situation, for when you want to know why an app ended up on a line.

- [Starting and quitting](#starting-and-quitting)
- [The window](#the-window)
- [Lines](#lines)
- [Choosing a line for an app](#choosing-a-line-for-an-app)
- [Combining your lines](#combining-your-lines)
- [When a line drops](#when-a-line-drops)
- [Phone data and caps](#phone-data-and-caps)
- [The tray icon](#the-tray-icon)
- [Windows settings Net Switch can change](#windows-settings-net-switch-can-change)
- [Where Net Switch keeps its files](#where-net-switch-keeps-its-files)
- [Updates](#updates)
- [Limitations](#limitations)
- [Troubleshooting](#troubleshooting)

## Starting and quitting

Open **Net Switch** from the Start menu. Windows asks for administrator
permission when Net Switch starts; that is what lets it move app traffic.
Routing turns on by itself.

**Start with Windows**, in the window's **Settings**, starts Net Switch when you
sign in, with its tray icon and without the window. It also stops the
permission prompt: turning it on sets up a scheduled task that Windows lets
start Net Switch's service without asking, and opening Net Switch uses that
task too. Turning it off removes the task, and so does uninstalling.

Closing the window keeps routing on, and the icon stays in the taskbar corner.
To get the window back, open Net Switch again from the Start menu, or click the
icon and press **See all** in its panel.

**Quit Net Switch** (bottom right of the window, or in the icon's right-click
menu) turns routing off and stops Net Switch. Every app then uses Windows'
normal connection again. The window only says it has closed once routing has
really stopped.

## The window

The top shows a card per line with its real speed, read from Windows, so it
includes everything on that line. Each card also shows:

- its health: the round trip of its last internet check, **Online** before the
  first check (or while routing is off), or what's wrong: **No internet**,
  **No address**, **No route**, or **Checking…** while a line that just came
  back waits for a check to pass;
- how many routed connections it is carrying right now, or which line its apps
  are using while it is down;
- **Main** on the main line, **Metered** on a line that costs data, and the
  data it has used.

With three lines or more the cards get slimmer, so the app list keeps its
room.

The list below shows each app that is using the internet, busiest first, with
its speed and its line.

"App" means one program file: all of Chrome, not one tab. Windows background
services share one program, so they show as one row. You can give that row a
line, but **Reconnect** isn't offered for it, because closing its connections
would interrupt Windows itself.

## Lines

A line is one internet connection, bound to one network adapter: a cable,
built-in Wi-Fi, a USB Wi-Fi adapter, or a phone with USB tethering.

- **The main line** is the first one. Apps you haven't given a line use it. On
  the first run it is the connection Windows uses for the internet, cable or
  not.
- **Add a line** appears when another connection is available. Adding,
  removing or reordering lines restarts routing for a moment.
- **Click a line** to rename it, make it the main line, mark it as metered,
  keep it for the apps you choose, give it a data cap, or remove it. Removing a
  line puts its apps back on the default.

The order of your lines matters when one drops: its apps move to the next line
in that order that works (see [When a line drops](#when-a-line-drops)).

If Windows renames an adapter (after a driver update, or a USB adapter in
another port), Net Switch follows it. A line whose adapter is missing may just
be unplugged, so it is kept until the adapter comes back. A wired main line
whose adapter is gone for good moves to the wired adapter Windows uses now.

## Choosing a line for an app

Each app's row offers its lines. Pick one to send the app there, or the default
to let it use the main line (or share while combining). **Add an app** lets you
choose a line for an app from the Start menu before it has ever started.

The choice is kept by the app's program file, and it stays when the app
updates itself into a new version folder (Discord, Slack and other apps do
that).

New connections move straight away. A connection that is already open stays
where it is. A download that is running keeps using its old line until it's
paused and resumed in that app. The row says what's left behind, and its meter
changes color once the traffic has really moved.

**Reconnect** (offered in that note) closes the app's connections that aren't
on its line, so the app opens new ones there. It tells you how many
connections it will interrupt and asks first. A running connection can't be
moved, only replaced, so some apps stop and need you to press resume. Try it on
a small download first.

Downloads that were already running when routing started also show up, with a
note to pause and resume them.

## Combining your lines

**Combine** spreads new connections from every app you haven't given a line
across your lines. Anything that opens several connections at once gets the
speed of several lines: speed tests, Steam, browsers loading a page, download
managers that download in parts.

Each line gets a share of the new connections:

- **Auto** follows each line's measured speed: a line that has shown it can go
  twice as fast gets about twice the share. The shares only change when a line
  has been busy enough to show its speed, at most once a minute.
- **Manual** lets you set each line's share with sliders, in steps of 5%.

A line kept for chosen apps, or one that has reached its data cap, takes no
share.

A single connection still uses one line. A large file downloaded over one
connection, which many installers and update tools do, gets one line's speed.
To use several lines for one big file, download it with a tool that splits it
into parts, such as `aria2c -x 8 <url>`.

Combining is not bonding. Bonding a single connection across lines needs a
server on the internet to put the pieces back together (Speedify and
OpenMPTCProuter work that way). Net Switch doesn't relay your traffic through
a server like that; each connection goes straight out through one of your
lines.

While combining, each app offers **Shared** and every line. **Shared** is where
every app starts. An app on a line stays on that line, and combining leaves it
alone; that includes the main line, which is how you keep an app off the other
lines.

While combining, websites can see your lines' different public addresses. If a
site keeps signing you out or a download fails, put that browser or app on one
line, or stop combining. Calls and games are often happier on one line too.

## When a line drops

- A line's apps move to the next line in your order that works, skipping lines
  kept for chosen apps and lines that have reached their cap.
- The main line's apps only move when another line works.
- If no other line works, apps stay where they are, and whichever line comes
  back first takes over as above.

When a line comes back, new connections go back to it. Connections that moved
while it was down stay where they are until they end, so a download or a call
that kept working isn't cut off. **Reconnect** on an app moves its connections
back at once.

A line counts as down when its address or default route is missing two checks
in a row, so one bad reading from Windows doesn't move anything.

While routing is on with two lines or more, Net Switch also checks each line's
internet through that line. Every 15 seconds it opens a connection to `1.1.1.1`
or `8.8.8.8` and closes it again, a few hundred bytes. Only when that fails does
it run a small HTTPS test (about 6 KB) to confirm, every 5 seconds until the
line passes. A line that is connected but reaches nothing (a phone with mobile
data off, a router whose own internet is down) counts as down after three
failed tests in a row, and as back after two passes. A line whose address has
just come back counts as back only once a test passes: a phone or router often
needs a moment before its internet works.

A line that's busy with a big transfer can be too slow to answer a test in
time. A failed test doesn't count while traffic is still crossing that line,
in either direction: the line is busy, not dead.

The checks use addresses rather than names, so a check never depends on
looking up a name through another line. If those addresses are blocked where
you are, change them under **Settings → Advanced → Test sites**.

If routing stops by itself or can't start, Net Switch starts it again after 5
seconds, then 15, 30, and every minute after that. **Turn off** always wins:
nothing restarts routing you turned off.

## Phone data and caps

Three settings on a line help with a phone's data plan:

- **Metered** marks the line as costing data. Net Switch counts what the
  adapter sends and receives, and the line's card shows it. On its own it
  changes nothing about routing. A phone line starts out metered.
- **Only apps I choose** keeps the line for the apps you put on it. It never
  takes over for another line and never takes part in combining. If it drops,
  its own apps use your other lines. It isn't offered for the main line, which
  carries every app without a line of its own.
- **Data cap** sets an amount per day or per month. A day starts at midnight; a
  month starts on the day you choose. Once the cap is reached, the line is left
  alone until the next period: its apps use your other lines, and its checks
  stop so they use no more of it. The count includes everything on that
  adapter, not only Net Switch's traffic.

## The tray icon

The icon shows a row of cells for each of your first three lines, in the
lines' colors: the main line on top (amber), the next one below (cyan), then a
third (violet). More lit cells mean more traffic on that line. A line that is
down stays faint, and all the cells turn gray while routing is off.

- **Point at it** to see each line's speed, or what is wrong with it.
- **Click it** for a small panel:
  - **Routing** and combining toggles (**Both lines**, or **Combine lines**
    with more than two);
  - your first three lines, each with its speed and health, and where its
    apps went while it is down; with more lines, **+N more** opens the window;
  - the three busiest apps. With up to three choices, pick an app's line right
    there; with more, **Change** opens the window;
  - a health line, and **Quit**.

  Click again, press Esc or click elsewhere to close it. The square button at
  the top and **See all** open the full window.
- **Right-click it** for **Open Net Switch**, **Show line notifications** and
  **Quit Net Switch**.

When a line goes down, comes back, uses up its data cap or can be used again,
Windows shows a notification. Clicking it opens Net Switch. A line that keeps
dropping and coming back notifies at most every 30 seconds, with its latest
news. To stop them, untick **Show line notifications**.

If the icon first appears under the ^ arrow, drag it onto the taskbar once.

## Windows settings Net Switch can change

Net Switch may offer two changes, each with its own button:

- **Make the main line the default.** Gives your other lines a lower priority,
  so Windows keeps using the main line while Net Switch is off.
- **Keep both connected.** Sets a Windows policy so Wi-Fi stays connected while
  a cable is plugged in. Without it, Windows may drop the Wi-Fi adapter.

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
| `%LOCALAPPDATA%\Net Switch` | Your settings (`settings.json` and a backup, and the tray's `tray-settings.json`), the data each line used (`usage.json`), `server.log`, `tray.log`, `launch.log` |
| `%ProgramData%\Net Switch` | The Windows undo record and the engine's files and log (administrators only) |

Settings from older versions, with a cable and a second connection, become two
lines the first time a newer version starts, with every app keeping its line.

If `settings.json` is damaged, Net Switch keeps a copy as
`settings.json.corrupt-…` and starts from the backup, or from the defaults if
the backup is damaged too. A single setting with an impossible value goes back
to its default on its own. Either way, `server.log` says what happened.

Logs stay small. `server.log` and the engine log start over in a `.1` file past
2 MB and 5 MB, `launch.log` past 1 MB, and `tray.log` is cleared at startup
once it passes 512 KB.

Uninstalling removes the program folder and the tasks that start Net Switch
with Windows. It removes `%ProgramData%\Net Switch` only once the Windows
changes are undone, or if you tell it to drop the undo record; if undoing
fails, the record stays so a reinstall can try again. Your settings and logs in
`%LOCALAPPDATA%\Net Switch` always stay, so a reinstall picks up where you left
off. Delete that folder if you don't want them.

## Updates

A minute after it starts, and then twice a day, Net Switch asks GitHub whether
a newer version is out. If one is, the window shows a notice with three
buttons:

- **Download** downloads the new installer in your browser. Run it: it closes
  Net Switch, updates it and keeps your settings. Open Net Switch again
  afterwards.
- **What's new** opens the release notes.
- **Not now** hides that version. You'll hear about the next one.

The tray icon's right-click menu offers the same download.

Net Switch never downloads or installs anything by itself: its server runs as
administrator, and installing should always be your decision. To stop the
checks, turn off **Check for updates** in the window's **Settings**.

## Limitations

- IPv6 is routed only while every line has an IPv6 address on the internet.
  Otherwise apps are told IPv6 is unavailable, which makes them use IPv4
  straight away instead of waiting on it. To always keep apps on IPv4, set
  `"ipv6": "off"` in `settings.json` while Net Switch is closed.
- One connection always uses one line (see [Combining](#combining-your-lines)).
- Traffic to devices on your own networks (router pages, printers, other PCs)
  isn't routed or listed per app. The line meters include it.
- Speeds are sampled once a second, so very short connections are undercounted.
- Net Switch is built and tested on Windows 11 x64 with one Ethernet adapter and
  one USB Wi-Fi adapter. Other setups (Windows 10, VPN software, phone
  tethering, three lines or more, non-English Windows) should work but haven't
  been tested much yet. Reports are welcome.

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
- **A website keeps signing me out.** Stop combining, or put that browser on one
  line.
- **A line shows Checking… for a long time.** Its address came back but its
  internet tests keep failing. Check the phone's mobile data or the router.
