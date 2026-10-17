import path from 'node:path';
import { appKey, UNKNOWN_APP } from './apps.mjs';
import { runPowerShellJson } from './ps.mjs';

const SVCHOST = 'c:\\windows\\system32\\svchost.exe';

// Display names and icons for executables, looked up once per path.
export class AppInfo {
  constructor({ lookup = runPowerShellJson } = {}) {
    this.cache = new Map();
    this.pending = new Set();
    this.attempted = new Set();
    this.lookup = lookup;
    this.running = false;
  }

  describe(processPath) {
    const key = appKey(processPath);
    if (key === UNKNOWN_APP) return { name: 'Unknown app', hasIcon: false, switchable: false, reconnectable: false };
    const fallbackName = path.win32.basename(processPath).replace(/\.exe$/i, '');
    // Windows services share one program file, so cutting "its" connections
    // would hit unrelated services: they can switch lines but not reconnect.
    if (key === SVCHOST) {
      return {
        name: 'Windows services',
        hasIcon: Boolean(this.cache.get(key)?.icon),
        switchable: true,
        reconnectable: false,
      };
    }
    const cached = this.cache.get(key);
    // A saved pin can point at a deleted version. Once the new executable
    // appears, retry a failed icon lookup using that file.
    if (!cached?.icon && !this.attempted.has(processPath.toLowerCase())) this.pending.add(processPath);
    return {
      name: cached?.name || fallbackName,
      hasIcon: Boolean(cached?.icon),
      switchable: true,
      reconnectable: true,
    };
  }

  icon(key) {
    // The picker can use its returned path; app rows already have a key.
    const icon = this.cache.get(appKey(key))?.icon;
    return icon ? Buffer.from(icon, 'base64') : null;
  }

  async lookupPending() {
    if (this.running || this.pending.size === 0) return;
    this.running = true;
    const paths = [...this.pending].slice(0, 25);
    try {
      const list =
        (await this.lookup(LOOKUP_SCRIPT, { timeoutMs: 30_000, args: { PATHS: JSON.stringify(paths) } })) ?? [];
      for (const item of list) {
        this.cache.set(appKey(item.path), { name: cleanName(item.name), icon: item.icon });
      }
    } catch {
      // Keep the file names; try again for new paths only.
    } finally {
      for (const item of paths) {
        if (!this.cache.has(appKey(item))) this.cache.set(appKey(item), { name: null, icon: null });
        this.attempted.add(item.toLowerCase());
        this.pending.delete(item);
      }
      this.running = false;
    }
  }
}

function cleanName(name) {
  const value = (name ?? '').trim();
  return value.length > 0 && value.length <= 60 ? value : null;
}

// Program paths arrive in $env:NETSWITCH_PATHS, never inside the script text.
const LOOKUP_SCRIPT = String.raw`
Add-Type -AssemblyName System.Drawing
$paths = $env:NETSWITCH_PATHS | ConvertFrom-Json
$list = foreach ($p in $paths) {
  $name = $null
  $icon = $null
  try {
    $info = (Get-Item -LiteralPath $p -ErrorAction Stop).VersionInfo
    $name = if ($info.FileDescription) { $info.FileDescription } else { $info.ProductName }
  } catch {}
  try {
    $source = [System.Drawing.Icon]::ExtractAssociatedIcon($p)
    if ($source) {
      $bitmap = $source.ToBitmap()
      $stream = New-Object System.IO.MemoryStream
      $bitmap.Save($stream, [System.Drawing.Imaging.ImageFormat]::Png)
      $icon = [Convert]::ToBase64String($stream.ToArray())
      $stream.Dispose(); $bitmap.Dispose(); $source.Dispose()
    }
  } catch {}
  [pscustomobject]@{ path = $p; name = $name; icon = $icon }
}
ConvertTo-Json -InputObject @($list) -Compress
`;
