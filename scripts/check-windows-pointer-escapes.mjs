import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';

// Compiler proof complements native completion/cancellation tests. It cannot
// prove an API's ownership contract; that audit is recorded separately.
assert.equal(process.env.GITHUB_ACTIONS, 'true', 'Run native pointer qualification in Actions');
assert.equal(process.platform, 'win32');
const env = { ...process.env, GOTOOLCHAIN: 'local', GOFLAGS: '-mod=vendor -p=2', GOMAXPROCS: '2' };
const version = spawnSync('go', ['version'], { env, encoding: 'utf8', windowsHide: true });
assert.equal(version.status, 0, version.stderr);
const build = spawnSync('go', ['build',
  '-gcflags=github.com/AyoubAchour/net-switch/internal/...=-m', '-gcflags=internal/poll=-m',
  './internal/engine/windows', './internal/wintun', './internal/winlock'],
{ env, encoding: 'utf8', windowsHide: true, maxBuffer: 16 << 20 });
assert.equal(build.status, 0, build.error?.message ?? build.stderr);
const lines = `${build.stdout}\n${build.stderr}`.split(/\r?\n/);
const sites = [
  ['pipe accept OVERLAPPED', /pipe_windows\.go:\d+:\d+: moved to heap: op$/],
  ['TCP receive OVERLAPPED and flags owner', /readiness_windows\.go:\d+:\d+: &socketWatch\{.*escapes to heap$/],
  ['ICMP caller request', /dial_windows\.go:\d+:\d+: leaking param: request$/],
  ['ICMP aligned reply', /dial_windows\.go:\d+:\d+: make\(\[\]uint64,.*escapes to heap$/],
  ['ICMP options', /dial_windows\.go:\d+:\d+: moved to heap: options$/],
  ['ICMP IPv6 source', /dial_windows\.go:\d+:\d+: moved to heap: src$/],
  ['ICMP IPv6 destination', /dial_windows\.go:\d+:\d+: moved to heap: dst$/],
  ['IP Helper pointer through Go wrapper', /dial_windows\.go:\d+:\d+: moved to heap: row$/],
  ['Go file/socket OVERLAPPED operation', /fd_windows\.go:\d+:\d+: new\(operation\) escapes to heap$/],
  ['Go file/socket pinned buffers', /fd_windows\.go:\d+:\d+: leaking param content: pinPtrs$/],
];
const proof = sites.map(([site, pattern]) => {
  const evidence = lines.find((line) => pattern.test(line));
  assert(evidence, `Missing heap proof for ${site}; inspect escape analysis before changing this assertion`);
  return { site, evidence };
});
console.log(`WINDOWS POINTER ESCAPE ${JSON.stringify({ version: version.stdout.trim(), proof })}`);
