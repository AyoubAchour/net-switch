import { execFile, spawn } from 'node:child_process';
import path from 'node:path';

// The server runs as administrator, so system tools are called by full path
// instead of whatever an earlier PATH entry happens to provide.
export const SYSTEM32 = path.join(process.env.SystemRoot ?? 'C:\\Windows', 'System32');
const POWERSHELL = path.join(SYSTEM32, 'WindowsPowerShell', 'v1.0', 'powershell.exe');
const TASKKILL = path.join(SYSTEM32, 'taskkill.exe');

function childEnv(args) {
  const env = { ...process.env };
  // Windows environment names ignore case; remove every spelling before setting ours.
  for (const name of Object.keys(env)) {
    if (/^(PSModulePath|NODE_OPTIONS)$/i.test(name)) delete env[name];
  }
  env.PSModulePath = [
    path.join(SYSTEM32, 'WindowsPowerShell', 'v1.0', 'Modules'),
    path.join(process.env.ProgramFiles ?? 'C:\\Program Files', 'WindowsPowerShell', 'Modules'),
  ].join(';');
  for (const [name, value] of Object.entries(args)) env[`NETSWITCH_${name}`] = String(value);
  return env;
}

export function killTree(pid) {
  if (!Number.isInteger(pid) || pid <= 0) return Promise.resolve();
  return new Promise((resolve) => {
    execFile(TASKKILL, ['/PID', String(pid), '/T', '/F'], { windowsHide: true, timeout: 5000 }, () => resolve());
  });
}

// Runs a Windows PowerShell 5.1 script as administrator.
// Values never go into the script text: PowerShell treats curly quotes as
// quotes too, so a crafted program path could break out of any string literal.
// Each value in `args` arrives as $env:NETSWITCH_<NAME> instead.
export function runPowerShell(script, { timeoutMs = 20_000, args = {} } = {}) {
  const prelude = '[Console]::OutputEncoding = [Text.Encoding]::UTF8\n';
  const encoded = Buffer.from(prelude + script, 'utf16le').toString('base64');
  const env = childEnv(args);
  return new Promise((resolve, reject) => {
    let timer;
    let cleanup;
    const child = execFile(
      POWERSHELL,
      ['-NoProfile', '-NonInteractive', '-EncodedCommand', encoded],
      { windowsHide: true, maxBuffer: 32 * 1024 * 1024, env },
      async (error, stdout, stderr) => {
        clearTimeout(timer);
        if (cleanup) {
          await cleanup;
          error ??= new Error(`PowerShell did not answer within ${timeoutMs} ms.`);
          error.killed = true;
        }
        if (error) {
          error.stdout = stdout;
          error.stderr = stderr;
          reject(error);
          return;
        }
        resolve(stdout);
      },
    );
    if (timeoutMs > 0) {
      timer = setTimeout(() => {
        // Kill descendants before the parent disappears from the process tree.
        cleanup = killTree(child.pid).then(() => {
          if (child.exitCode === null && child.signalCode === null) child.kill();
        });
      }, timeoutMs);
    }
  });
}

// A long-running PowerShell script whose output the caller reads line by line.
export function spawnPowerShell(script, { args = {} } = {}) {
  const prelude = '[Console]::OutputEncoding = [Text.Encoding]::UTF8\n';
  const encoded = Buffer.from(prelude + script, 'utf16le').toString('base64');
  const env = childEnv(args);
  return spawn(POWERSHELL, ['-NoProfile', '-NonInteractive', '-EncodedCommand', encoded], {
    windowsHide: true,
    env,
    stdio: ['ignore', 'pipe', 'pipe'],
  });
}

export async function runPowerShellJson(script, options) {
  const output = (await runPowerShell(script, options)).trim();
  return output ? JSON.parse(output) : null;
}

export function runFile(file, args, { timeoutMs = 20_000 } = {}) {
  return new Promise((resolve, reject) => {
    execFile(file, args, { windowsHide: true, timeout: timeoutMs }, (error, stdout, stderr) => {
      if (error) {
        error.stdout = stdout;
        error.stderr = stderr;
        reject(error);
        return;
      }
      resolve(stdout);
    });
  });
}
