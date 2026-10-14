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
3. Start it with `launch.ps1`:

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
  run next to a real copy. Its tray icon:
  `powershell -NoProfile -ExecutionPolicy Bypass -File tray.ps1 -DataDir data-test`.

## Tests

```powershell
npm test
```

The tray tests compile `lib\tray.cs` with Windows PowerShell 5.1, so that code
must stay C# 5: no string interpolation, no `?.`, no expression-bodied members.

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

This downloads the pinned Node.js, sing-box and
[Inno Setup](https://jrsoftware.org/isinfo.php) files listed in
`packaging\versions.json`, checks their hashes, and builds
`dist\NetSwitch-Setup-<version>-x64.exe`. Pushing a `v*` tag builds
and publishes a release on GitHub; the tag must match `package.json` and have
a section in `CHANGELOG.md`.

## Style

- Plain JavaScript modules, no build step, no dependencies. Please keep it that
  way unless there's a strong reason.
- Comments explain why, in plain sentences.
- Text in the window should say what is happening and what to do next, in
  words a non-technical person understands.
