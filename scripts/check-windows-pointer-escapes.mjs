import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { readFileSync } from 'node:fs';

// Compiler proof complements native completion/cancellation tests. It cannot
// prove an API's ownership contract; that audit is recorded separately.
assert.equal(process.env.GITHUB_ACTIONS, 'true', 'Run native pointer qualification in Actions');
assert.equal(process.platform, 'win32');
const env = { ...process.env, GOTOOLCHAIN: 'local', GOFLAGS: '-mod=vendor -p=2', GOMAXPROCS: '2' };
const version = spawnSync('go', ['version'], { env, encoding: 'utf8', windowsHide: true });
assert.equal(version.status, 0, version.stderr);
function functionRange(file, declaration) {
  const source = readFileSync(file, 'utf8').split(/\r?\n/);
  const starts = source.flatMap((line, index) => line.startsWith(declaration) ? [index] : []);
  assert.equal(starts.length, 1, `Expected one declaration for ${declaration}`);
  const start = starts[0];
  let end = source.findIndex((line, index) => index > start && line.startsWith('func '));
  if (end < 0) end = source.length;
  return { file, first: start + 1, last: end };
}
const accept = functionRange('internal/engine/windows/pipe_windows.go', 'func (p *Pipe) Accept(');
const watch = functionRange('internal/engine/windows/readiness_windows.go', 'func (p *readiness) watch(');
const echo = functionRange('internal/engine/windows/dial_windows.go', 'func (d *Dialer) Echo(');
const mtu = functionRange('internal/engine/windows/dial_windows.go', 'func (s *udpSocket) pathMTU(');
const registrar = functionRange('internal/wintun/registrar_windows.go', 'func startRegistrar(');
const modes = functionRange('internal/engine/windows/readiness_modes_windows.go', 'func querySocketCompletionModes(');
const pipeConnNew = functionRange('internal/engine/windows/pipe_windows.go', 'func newPipeConn(');
const pipeTransfer = functionRange('internal/engine/windows/pipe_windows.go', 'func (c *pipeConn) transfer(');
const session = functionRange('internal/wintun/session_windows.go', 'func (a *Adapter) startSession(');
const udpReady = functionRange('internal/engine/windows/udp_readiness_windows.go', 'func newUDPReadiness(');
const heapOpen = functionRange('internal/engine/windows/heap_profile_windows.go', 'func openHeapProfile(');
const xsysWait = functionRange('vendor/golang.org/x/sys/windows/syscall_windows.go', 'func WaitForMultipleObjects(');
const terminalWrite = functionRange('internal/engine/windows/terminal_pipe_windows_test.go', 'func (p *terminalPipeObserver) Write(');
const terminalTest = functionRange('internal/engine/windows/terminal_pipe_windows_test.go', 'func TestTerminalLossCancelsRealEnginePipeBlockedWrite(');
const sites = [
  ['pipe accept OVERLAPPED', /pipe_windows\.go:\d+:\d+: moved to heap: op$/, accept],
  // Connected pipe I/O: both OVERLAPPEDs live in the connection, and each
  // payload is pinned (so heap-allocated) until its operation has finished.
  ['pipe connection OVERLAPPED owner', /pipe_windows\.go:\d+:\d+: &pipeConn\{.*escapes to heap$/, pipeConnNew],
  ['pipe connection payload', /pipe_windows\.go:\d+:\d+: leaking param: b$/, pipeTransfer],
  ['TCP receive OVERLAPPED and flags owner', /readiness_windows\.go:\d+:\d+: &socketWatch\{.*escapes to heap$/, watch],
  ['ICMP caller request', /dial_windows\.go:\d+:\d+: leaking param: request$/, echo],
  ['ICMP aligned reply', /dial_windows\.go:\d+:\d+: make\(\[\]uint64,.*escapes to heap$/, echo],
  ['ICMP options', /dial_windows\.go:\d+:\d+: moved to heap: options$/, echo],
  ['ICMP IPv6 source', /dial_windows\.go:\d+:\d+: moved to heap: src$/, echo],
  ['ICMP IPv6 destination', /dial_windows\.go:\d+:\d+: moved to heap: dst$/, echo],
  ['IP Helper pointer through Go wrapper', /dial_windows\.go:\d+:\d+: moved to heap: row$/, mtu],
  ['registrar job limits', /registrar_windows\.go:\d+:\d+: moved to heap: limits$/, registrar],
  ['registrar job UI limits', /registrar_windows\.go:\d+:\d+: moved to heap: ui$/, registrar],
  ['registrar inherited handle array', /registrar_windows\.go:\d+:\d+: make\(\[\]windows.Handle,.*escapes to heap$/, registrar],
  ['registrar atomic job-list array', /registrar_windows\.go:\d+:\d+: \[\]windows.Handle\{.*escapes to heap$/, registrar],
  ['completion-mode output flags', /readiness_modes_windows\.go:\d+:\d+: moved to heap: modes$/, modes],
  ['completion-mode status block', /readiness_modes_windows\.go:\d+:\d+: moved to heap: status$/, modes],
  ['Go file/socket OVERLAPPED operation', /fd_windows\.go:\d+:\d+: new\(operation\) escapes to heap$/],
  ['Go file/socket pinned buffers', /fd_windows\.go:\d+:\d+: leaking param content: pinPtrs$/],
  // Wait arrays live in heap owners and go through internal/platform/winapi,
  // which converts the address only inside the non-splitting SyscallN call.
  ['Wintun read wait array owner', /session_windows\.go:\d+:\d+: &Session\{.*escapes to heap$/, session],
  ['UDP readiness wait arrays owner', /udp_readiness_windows\.go:\d+:\d+: &udpReadiness\{.*escapes to heap$/, udpReady],
  // Old-path evidence, not a heap proof: x/sys leaves a caller's handle array
  // where the caller put it, so a stack array can move before the kernel call.
  ['x/sys WaitForMultipleObjects keeps caller arrays in place', /syscall_windows\.go:\d+:\d+: handles does not escape$/, xsysWait],
];
const handlecheckSites = [
  ['heap capture wait array owner', /heap_profile_windows\.go:\d+:\d+: &heapProfile\{.*escapes to heap$/, heapOpen],
];

// Source gate: no Go file outside vendor may call the x/sys wait wrapper,
// except the deliberate negative control that reproduces its hazard.
const listed = spawnSync('git', ['grep', '-n', '-F', 'windows.WaitForMultipleObjects(', '--', '*.go', ':!vendor/'],
  { encoding: 'utf8', windowsHide: true });
assert(listed.status === 0 || listed.status === 1, listed.stderr);
const unsafeWaits = listed.stdout.split(/\r?\n/).filter(Boolean)
  .filter((line) => !line.startsWith('internal/platform/winapi/stack_move_windows_test.go:'));
assert.deepEqual(unsafeWaits, [], 'Use internal/platform/winapi for handle-array waits');
const helperSource = readFileSync('internal/platform/winapi/winapi_windows.go', 'utf8');
assert.match(helperSource, /syscall\.SyscallN\(addr, uintptr\(len\(handles\)\), uintptr\(unsafe\.Pointer\(&handles\[0\]\)\), all, uintptr\(milliseconds\)\)/,
  'winapi must convert the array address inside the SyscallN argument list');
assert.equal(helperSource.match(/&handles\[0\]/g)?.length, 1, 'winapi must not take the array address anywhere else');

for (const tags of ['', 'netswitch_handlecheck']) {
  const build = spawnSync('go', ['build',
    '-gcflags=github.com/AyoubAchour/net-switch/internal/...=-m', '-gcflags=internal/poll=-m',
    '-gcflags=golang.org/x/sys/windows=-m',
    './internal/engine/windows', './internal/wintun', './internal/winlock'],
  { env: { ...env, GOFLAGS: `${env.GOFLAGS}${tags ? ` -tags=${tags}` : ''}` },
    encoding: 'utf8', windowsHide: true, maxBuffer: 16 << 20 });
  assert.equal(build.status, 0, build.error?.message ?? build.stderr);
  const lines = `${build.stdout}\n${build.stderr}`.split(/\r?\n/);
  const proof = [...sites, ...(tags ? handlecheckSites : [])].map(([site, pattern, scope]) => {
    const matches = lines.filter((line) => pattern.test(line))
      .map((line) => line.match(/^(.+\.go):(\d+):(\d+): (.*)$/));
    const match = matches.find((m) => m && (!scope || (m[1].replaceAll('\\', '/').endsWith(scope.file) &&
      Number(m[2]) >= scope.first && Number(m[2]) <= scope.last)));
    assert(match, `Missing heap proof for ${site} in its owning function; inspect before changing this assertion`);
    // Avoid Actions' filename:line:column error matcher for successful proof.
    return { site, file: match[1], line: Number(match[2]), column: Number(match[3]), message: match[4] };
  });
  console.log(`WINDOWS POINTER ESCAPE ${JSON.stringify({ version: version.stdout.trim(), tags: tags || 'release', proof })}`);
}

// This observer is test-only, but exercises a real overlapped pipe write. Its
// explicit retention/pin must have compiler evidence too, not just a comment
// citing the standard library's separate operation allocation.
const fixture = spawnSync('go', ['test', '-c', '-o', 'dist/windows-pointer-audit.test.exe',
  '-gcflags=github.com/AyoubAchour/net-switch/internal/engine/windows=-m', './internal/engine/windows'],
{ env: { ...env, GOFLAGS: `${env.GOFLAGS} -tags=netswitch_handlecheck` }, encoding: 'utf8', windowsHide: true, maxBuffer: 16 << 20 });
assert.equal(fixture.status, 0, fixture.error?.message ?? fixture.stderr);
const fixtureLines = `${fixture.stdout}\n${fixture.stderr}`.split(/\r?\n/);
const fixtureProof = [
  ['terminal pipe fixture payload', /leaking param: b$/, terminalWrite],
  ['terminal pipe fixture owner', /&terminalPipeObserver\{.*escapes to heap$/, terminalTest],
].map(([site, pattern, scope]) => {
  const match = fixtureLines.filter((line) => pattern.test(line))
    .map((line) => line.match(/^(.+\.go):(\d+):(\d+): (.*)$/))
    .find((m) => m && m[1].replaceAll('\\', '/').endsWith(scope.file) && Number(m[2]) >= scope.first && Number(m[2]) <= scope.last);
  assert(match, `Missing heap proof for ${site} in its owning function`);
  return { site, file: match[1], line: Number(match[2]), column: Number(match[3]), message: match[4] };
});
console.log(`WINDOWS FIXTURE POINTER ESCAPE ${JSON.stringify({ version: version.stdout.trim(), proof: fixtureProof })}`);
