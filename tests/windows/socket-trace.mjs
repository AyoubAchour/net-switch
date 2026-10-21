import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { access } from 'node:fs/promises';
import path from 'node:path';

assert.equal(process.env.GITHUB_ACTIONS, 'true', 'Socket tracing is hosted-only');
assert.equal(process.env.RUNNER_ENVIRONMENT, 'github-hosted', 'Socket tracing is hosted-only');
assert.equal(process.env.NETSWITCH_SOCKET_DIAGNOSTICS, '1');
assert(['x64', 'arm64'].includes(process.arch), `Unsupported diagnostic architecture ${process.arch}`);
const debuggerExe = path.join(process.env['ProgramFiles(x86)'], 'Windows Kits', '10', 'Debuggers', process.arch, 'cdb.exe');
await access(debuggerExe);
console.log(`SOCKET DEBUGGER ${JSON.stringify({ architecture: process.arch, path: debuggerExe })}`);
const executable = path.resolve('dist/windows-test/socket-diagnostics.exe');
await access(executable);

// Enabling OS handle tracing also raises first-chance invalid-handle
// exceptions. A debugger must handle that notification before Go's runtime
// terminates. Keep the native BADREF record and the original NTSTATUS checks:
// handling the notification cannot turn a failing socket assertion into PASS.
const commands = 'sxe -c ".echo NETSWITCH_BAD_HANDLE_EXCEPTION; .exr -1; !htrace; gh" 0xc0000008; g';
const child = spawn(debuggerExe, ['-G', '-hd', '-c', commands, executable,
  '-test.v', '-test.count=1', '-test.failfast', '-test.timeout=10m',
  '-test.run=^(TestSocketHandleTrace(Control|Churn|PanicCapture)|TestReadinessHalfClose(AndCancellation|AfterCollection)|TestReadyUDPDoesNotConsumeDatagrams)$'],
{ windowsHide: true, env: { ...process.env, _NT_SYMBOL_PATH: '', _NT_ALT_SYMBOL_PATH: '' },
  stdio: ['ignore', 'pipe', 'pipe'] });
let buffer = '', output = '', expired = false, notifications = 0;
const timeout = setTimeout(() => {
  expired = true;
  child.kill(); // This debugger and its debuggee were started by this fixture.
}, 11 * 60_000);
const read = (chunk, destination) => {
  destination.write(chunk);
  buffer += chunk.toString();
  // Keep the verdict/control lines only; the complete trace stays in Actions.
  for (;;) {
    const end = buffer.indexOf('\n');
    if (end < 0) break;
    const line = buffer.slice(0, end).trim();
    buffer = buffer.slice(end + 1);
    if (line === 'NETSWITCH_BAD_HANDLE_EXCEPTION' && ++notifications > 2) {
      child.kill(); // Bound a non-continuable/repeating debugger notification.
    }
    if (/CONTROL PASS|^PASS$|^FAIL$|--- FAIL:|panic:|fatal error:|NETSWITCH_BAD_HANDLE_EXCEPTION/.test(line)) output += `${line}\n`;
  }
};
child.stdout.on('data', (chunk) => read(chunk, process.stdout));
child.stderr.on('data', (chunk) => read(chunk, process.stderr));
const status = await new Promise((resolve, reject) => {
  child.once('error', reject);
  child.once('exit', (code, signal) => resolve({ code, signal }));
}).finally(() => clearTimeout(timeout));
assert(!expired, 'The socket diagnostic debugger timed out');
assert.equal(status.signal, null, 'The socket diagnostic debugger was interrupted');
assert.equal(status.code, 0, 'The socket diagnostic debugger failed');
for (const marker of ['SOCKET TRACE CONTROL PASS', 'SOCKET TABLE CONTROL PASS', 'SOCKET TRANSFER CONTROL PASS', 'SOCKET PANIC CONTROL PASS',
  'NETSWITCH_BAD_HANDLE_EXCEPTION']) {
  assert(output.includes(marker), `The required trace control did not run: ${marker}`);
}
assert(/^PASS$/m.test(output), 'The Go socket suite never completed successfully');
assert(!/^FAIL$|--- FAIL:|panic:|fatal error:/m.test(output), 'The original socket assertion failed');
assert.equal(notifications, 1,
  'An invalid-handle exception occurred outside the deliberate control');
