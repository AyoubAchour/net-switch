import assert from 'node:assert/strict';
import { win32 as path } from 'node:path';
import { test } from 'node:test';
import { canAutostart, taskDefinitions } from '../lib/autostart.mjs';

const PROGRAM_FILES = 'C:\\Program Files';
const ROOT = 'C:\\Program Files\\Net Switch';
const NODE = path.join(ROOT, 'runtime', 'node.exe');
const HELPER = path.join(ROOT, 'helper', 'netswitch-helper.exe');
const exists = (file) => [NODE, HELPER].some((known) => file.toLowerCase() === known.toLowerCase());

test('only an installed copy in Program Files, run by its own Node.js, may start with Windows', () => {
  assert.equal(canAutostart({ root: ROOT, nodePath: NODE, programFiles: PROGRAM_FILES, exists }), true);
  // Any letter case.
  assert.equal(canAutostart({ root: ROOT.toLowerCase(), nodePath: NODE.toUpperCase(), programFiles: PROGRAM_FILES, exists }), true);
  // A source checkout: a folder its owner can change without administrator rights.
  const checkout = 'C:\\Users\\Ayoub\\Desktop\\net-switch';
  assert.equal(
    canAutostart({ root: checkout, nodePath: path.join(checkout, 'runtime', 'node.exe'), programFiles: PROGRAM_FILES, exists: () => true }),
    false,
  );
  // Installed, but run by another Node.js.
  assert.equal(canAutostart({ root: ROOT, nodePath: 'C:\\Program Files\\nodejs\\node.exe', programFiles: PROGRAM_FILES, exists }), false);
  // A folder that only starts with the same letters.
  assert.equal(
    canAutostart({ root: 'C:\\Program Files Evil\\Net Switch', nodePath: 'C:\\Program Files Evil\\Net Switch\\runtime\\node.exe', programFiles: PROGRAM_FILES, exists: () => true }),
    false,
  );
  // Windows didn't say where Program Files is.
  assert.equal(canAutostart({ root: ROOT, nodePath: NODE, programFiles: null, exists }), false);
  // Without the helper the task starts the server through, it would fail at sign-in.
  assert.equal(canAutostart({ root: ROOT, nodePath: NODE, programFiles: PROGRAM_FILES, exists: (file) => file === NODE }), false);
});

test('the service task runs the installed server as administrator on request, without a window; the sign-in task runs the launcher as the person', () => {
  const { server, signIn } = taskDefinitions({
    root: ROOT,
    nodePath: NODE,
    userDir: 'C:\\Users\\A & B\\AppData\\Local\\Net Switch',
    machineDir: 'C:\\ProgramData\\Net Switch',
  });
  assert.match(server, /<RunLevel>HighestAvailable<\/RunLevel>/);
  assert.match(server, /<Triggers><\/Triggers>/, 'started by launch.ps1 only');
  // Through the windowless helper: node.exe run by the task directly opens a console window.
  assert.match(server, /<Command>C:\\Program Files\\Net Switch\\helper\\netswitch-helper\.exe<\/Command>/);
  // Text is escaped for XML, and every path is quoted.
  assert.match(
    server,
    /<Arguments>run &#34;C:\\Program Files\\Net Switch\\runtime\\node\.exe&#34; &#34;C:\\Program Files\\Net Switch\\server\.mjs&#34; --user-data &#34;C:\\Users\\A &#38; B\\AppData\\Local\\Net Switch&#34; --machine-data &#34;C:\\ProgramData\\Net Switch&#34;<\/Arguments>/,
  );
  assert.match(signIn, /<RunLevel>LeastPrivilege<\/RunLevel>/);
  assert.match(signIn, /<LogonTrigger><Enabled>true<\/Enabled><UserId>__NETSWITCH_USER_SID__<\/UserId>/);
  assert.match(signIn, /-File &#34;C:\\Program Files\\Net Switch\\launch\.ps1&#34; -Background<\/Arguments>/);
  for (const xml of [server, signIn]) {
    // Normal priority, no time limit, and not stopped on battery: it runs all day.
    assert.match(xml, /<Priority>4<\/Priority>/);
    assert.match(xml, /<ExecutionTimeLimit>PT0S<\/ExecutionTimeLimit>/);
    assert.match(xml, /<StopIfGoingOnBatteries>false<\/StopIfGoingOnBatteries>/);
    assert.match(xml, /<UserId>__NETSWITCH_USER_SID__<\/UserId>\s*<LogonType>InteractiveToken<\/LogonType>/);
  }
});
