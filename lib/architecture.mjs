import { execFileSync } from 'node:child_process';
import path from 'node:path';
import { SYSTEM32 } from './ps.mjs';

// HKLM\SYSTEM is shared across architectures, unlike the emulated process's
// environment and Node's architecture APIs:
// https://learn.microsoft.com/windows/win32/winprog64/shared-registry-keys
const ENVIRONMENT_KEY = 'HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Environment';

export function createArchitectureReader({ platform = process.platform, arch = process.arch, query = execFileSync } = {}) {
  let result;
  let failure;
  let checked = false;
  return () => {
    if (!checked) {
      checked = true;
      if (platform !== 'win32') return (result = arch);
      try {
        const output = query(path.join(SYSTEM32, 'reg.exe'), ['query', ENVIRONMENT_KEY, '/v', 'PROCESSOR_ARCHITECTURE'], {
          encoding: 'utf8', windowsHide: true, timeout: 5000, stdio: ['ignore', 'pipe', 'pipe'],
        });
        const value = /^\s*PROCESSOR_ARCHITECTURE\s+REG_SZ\s+(\S+)\s*$/im.exec(output)?.[1].toUpperCase();
        result = { AMD64: 'x64', ARM64: 'arm64' }[value];
        if (!result) throw new Error(`unsupported or missing PROCESSOR_ARCHITECTURE: ${value ?? '(missing)'}`);
      } catch (error) {
        // Never silently choose an emulated architecture. The updater/engine
        // already report failures; keep the reason and avoid repeating the query.
        failure = new Error(`Could not read Windows architecture from the registry: ${error.message}`, { cause: error });
      }
    }
    if (failure) throw failure;
    return result;
  };
}

// One lazy query for the lifetime of this process, shared by engine and updater.
export const nativeArchitecture = createArchitectureReader();
