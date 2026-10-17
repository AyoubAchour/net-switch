# Contributing

Thanks for wanting to help. Bug reports with logs and a clear description of
your setup are just as useful as code.

## Running from source

You need Windows 10 or 11 (x64), [Node.js](https://nodejs.org) 22 or newer, and
Git. There are no npm dependencies to install.

1. Clone the repository.
2. Download sing-box 1.14.2 for Windows from its
   [release page](https://github.com/SagerNet/sing-box/releases/tag/v1.14.2)
   (`sing-box-1.14.2-windows-amd64.zip`). Put `sing-box.exe` and
   `libcronet.dll` in `engine\`. Net Switch refuses to start the engine unless
   both match `engine\SHA256SUMS.txt`.
3. Optional: build the small native helper that reads the line speeds and the
   connections that go around routing:

   ```powershell
   npm run build:helper
   ```

   This downloads the Go version pinned in `packaging\versions.json` into
   `dist\cache` (nothing is installed on your PC), runs the helper's tests and
   builds `helper\bin\netswitch-helper.exe`. Without it, Net Switch reads the
   same things with PowerShell instead: everything works, it just uses about
   200 MB more memory. `server.log` says which one is used. Quit Net Switch
   before rebuilding the helper, since Windows won't replace a running program.
4. Optional: build the tray icon as a small program of its own:

   ```powershell
   npm run build:tray
   ```

   This compiles `lib\tray.cs` and `lib\tray-main.cs` into
   `tray\bin\NetSwitchTray.exe` with the C# compiler that comes with Windows
   (part of .NET Framework 4), so nothing is downloaded. Without it,
   `launch.ps1` runs `tray.ps1`, which compiles the same code at each start
   and keeps PowerShell running for the icon: everything works, it just uses
   about 50 MB more memory. `launch.ps1` also falls back to `tray.ps1` when
   `lib\tray.cs` is newer than the build (`launch.log` says so), so rebuild
   after changing the tray. Quit Net Switch before rebuilding it, since
   Windows won't replace a running program.
5. Start it with `launch.ps1`:

   ```powershell
   powershell -NoProfile -ExecutionPolicy Bypass -File launch.ps1
   ```

   From a source checkout, everything Net Switch writes goes to `data\`.

## Ways to work without touching your network

- **Demo window.** `node dev/demo-server.mjs` serves the real window with
  made-up apps and traffic at `http://127.0.0.1:47841/#token=demo`. No
  administrator rights, no second connection. Good for UI work and screenshots.
- **Test mode.** `node server.mjs --dev-proxy` runs the real server and engine,
  but only routes traffic you send through its local proxy (the window's status
  shows the port). It keeps its files in `data-test\` and uses other ports, so it can
  run next to a real copy. Its tray icon: `tray\bin\NetSwitchTray.exe -DataDir data-test`,
  or without that build,
  `powershell -NoProfile -ExecutionPolicy Bypass -File tray.ps1 -DataDir data-test`.

## Tests

```powershell
npm test
```

The tray tests compile `lib\tray.cs` with Windows PowerShell 5.1, and the
tray program is built with the C# compiler that comes with Windows, so that
code (and `lib\tray-main.cs`) must stay C# 5: no string interpolation, no `?.`,
no expression-bodied members.

When the tray program is built, `npm test` also starts it for a few seconds on
a temporary folder, so an icon may appear briefly. When the native helper is
built, `npm test` also runs it and checks its output against the PowerShell
version. Without them, those tests are skipped and say so. The helper's own Go
tests run in `npm run build:helper`, which also checks `gofmt` and `go vet`.

Tests can't plug and unplug network cables. If you change routing, failover or
the Windows settings code, please also check by hand, and say what you tried
in the pull request:

- unplug the cable, then the second connection, and plug them back in;
- turn off the phone's mobile data (or the second router's internet) while the
  Wi-Fi stays connected;
- quit and reopen Net Switch, and put the PC to sleep and wake it.

## Building the installer

```powershell
npm run build
```

This downloads the pinned Node.js, sing-box, Go and
[Inno Setup](https://jrsoftware.org/isinfo.php) files listed in
`packaging\versions.json`, checks their hashes, builds the native helper and
the tray program, and builds `dist\NetSwitch-Setup-<version>-x64.exe`. In
`dist\STAGE-SHA256SUMS.txt`, the tray program's hash changes with every
build, because the compiler Windows ships stamps each build with its own time
and ID. Pushing a `v*` tag builds and publishes a release on GitHub; the tag
must match `package.json` and have a section in `CHANGELOG.md`.

## Style

- Plain JavaScript modules, no build step, no dependencies. Please keep it that
  way unless there's a strong reason.
- The native helper (`helper\`) is Go, laid out by `gofmt`, with
  `golang.org/x/sys` as its only dependency. Its output lines must stay
  exactly the same as the PowerShell fallback's in `lib\monitor.mjs`.
- The tray program's start (`lib\tray-main.cs`) does what `tray.ps1` does
  before it calls `Tray.Run`: the same data folder, log and single-copy rule.
  Change both together.
- Comments explain why, in plain sentences.
- Text in the window should say what is happening and what to do next, in
  words a non-technical person understands.
