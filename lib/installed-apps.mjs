import { readdir, stat } from 'node:fs/promises';
import path from 'node:path';
import { appKey } from './apps.mjs';
import { runPowerShellJson } from './ps.mjs';

const CACHE_MS = 5 * 60_000;
const MAINTENANCE_NAME = /(?:^|[\s._-])(?:uninstall(?:er)?|unins\d*|setup|installer)(?:$|[\s._-])/i;
const MAINTENANCE_EXE = /(?:unins(?:tall(?:er)?)?\d*|setup|installer)\.exe$/i;

// Compare numeric parts, not folder names: app-1.0.10 is newer than app-1.0.9.
function newestFirst(a, b) {
  const left = a.slice(4).split('.').map(Number);
  const right = b.slice(4).split('.').map(Number);
  for (let i = 0; i < Math.max(left.length, right.length); i += 1) {
    const difference = (right[i] ?? 0) - (left[i] ?? 0);
    if (difference) return difference;
  }
  return b.localeCompare(a);
}

export class InstalledApps {
  constructor({ appInfo, readShortcuts = runPowerShellJson, readDirectory = readdir, fileStat = stat, now = Date.now } = {}) {
    this.appInfo = appInfo;
    this.readShortcuts = readShortcuts;
    this.readDirectory = readDirectory;
    this.fileStat = fileStat;
    this.now = now;
    this.cached = null;
    this.expiresAt = 0;
    this.pending = null;
  }

  async list() {
    if (!this.cached || this.now() >= this.expiresAt) {
      if (!this.pending) {
        this.pending = this.scan().then((apps) => {
          this.cached = apps;
          this.expiresAt = this.now() + CACHE_MS;
        }).finally(() => { this.pending = null; });
      }
      await this.pending;
    }
    const apps = this.cached.map((app) => ({
      ...app,
      ...(this.appInfo ? { hasIcon: this.appInfo.describe(app.path).hasIcon } : {}),
    }));
    // Icons use the existing cache and endpoint. Warm them in batches even
    // when routing is off; subsequent picker requests see the ready icons.
    if (this.appInfo) void this.lookupIcons();
    return apps;
  }

  async lookupIcons() {
    while (this.appInfo.pending.size > 0 && !this.appInfo.running) {
      await this.appInfo.lookupPending();
    }
  }

  async isFile(file) {
    try {
      return (await this.fileStat(file)).isFile();
    } catch (error) {
      if (['ENOENT', 'ENOTDIR', 'EACCES', 'EPERM'].includes(error.code)) return false;
      throw error;
    }
  }

  async target(shortcut) {
    let target = shortcut.path;
    if (typeof target !== 'string' || !/\.exe$/i.test(target)) return null;
    if (path.win32.basename(target).toLowerCase() === 'update.exe') {
      const match = /(?:^|\s)--processStart(?:\s+|=)(?:"([^"\\/]+\.exe)"|([^\s"\\/]+\.exe))(?=\s|$)/i.exec(shortcut.args ?? '');
      if (!match) return null;
      const executable = match[1] ?? match[2];
      const directory = path.win32.dirname(target);
      let folders;
      try {
        folders = await this.readDirectory(directory, { withFileTypes: true });
      } catch (error) {
        if (['ENOENT', 'ENOTDIR', 'EACCES', 'EPERM'].includes(error.code)) return null;
        throw error;
      }
      const versions = folders.filter((item) => item.isDirectory() && /^app-\d+(?:\.\d+)+$/i.test(item.name))
        .map((item) => item.name).sort(newestFirst);
      target = null;
      for (const version of versions) {
        const candidate = path.win32.join(directory, version, executable);
        if (await this.isFile(candidate)) {
          target = candidate;
          break;
        }
      }
    }
    if (!target || MAINTENANCE_EXE.test(path.win32.basename(target))) return null;
    return await this.isFile(target) ? target : null;
  }

  async scan() {
    try {
      const shortcuts = await this.readShortcuts(START_MENU_SCRIPT, { timeoutMs: 20_000 }) ?? [];
      const apps = new Map();
      // Sorting first makes the chosen name predictable when both menus have
      // a shortcut for the same app.
      shortcuts.sort((a, b) => String(a.name).localeCompare(String(b.name)) || String(a.path).localeCompare(String(b.path)));
      for (const shortcut of shortcuts) {
        if (typeof shortcut.name !== 'string' || !shortcut.name.trim() || MAINTENANCE_NAME.test(shortcut.name)) continue;
        if (/(?:^|\s)[/-]+(?:uninstall|setup)(?:\s|$)/i.test(shortcut.args ?? '')) continue;
        const target = await this.target(shortcut);
        if (target && !apps.has(appKey(target))) apps.set(appKey(target), { name: shortcut.name.trim(), path: target });
      }
      return [...apps.values()].sort((a, b) => a.name.localeCompare(b.name));
    } catch (error) {
      throw new Error(`Couldn’t read the apps in the Start menu. ${error.message}`, { cause: error });
    }
  }
}

// Resolve every shortcut in one PowerShell process. A broken shortcut is
// skipped, but a failed menu scan is reported rather than cached as no apps.
const START_MENU_SCRIPT = String.raw`
$ErrorActionPreference = 'Stop'
$shell = New-Object -ComObject WScript.Shell
try {
  $roots = @(
    (Join-Path $env:APPDATA 'Microsoft\Windows\Start Menu\Programs'),
    (Join-Path $env:ProgramData 'Microsoft\Windows\Start Menu\Programs')
  )
  $list = foreach ($root in $roots) {
    if (-not (Test-Path -LiteralPath $root -PathType Container)) { continue }
    foreach ($file in Get-ChildItem -LiteralPath $root -Filter '*.lnk' -Recurse -File) {
      $shortcut = $null
      try {
        $shortcut = $shell.CreateShortcut($file.FullName)
        [pscustomobject]@{ name = $file.BaseName; path = $shortcut.TargetPath; args = $shortcut.Arguments }
      } catch {
        # One damaged shortcut must not hide the rest of the menu.
      } finally {
        if ($shortcut) { [void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($shortcut) }
      }
    }
  }
  ConvertTo-Json -InputObject @($list) -Compress
} finally {
  [void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($shell)
}
`;
