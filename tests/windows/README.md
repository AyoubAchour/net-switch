# Windows acceptance

These programs run only on disposable GitHub-hosted Windows runners. Do not run
the gateway, clients, server, engine or PowerShell network scripts on a developer's
PC. Local checks are syntax, vet and build only, at Idle priority with two cores.
All tests run in CI.

See the [Windows HTTP failure investigation](ci-failure-investigation.md) for the
original control reset and cap-setup timeout, retained diagnostics and repeat counts.

The existing app and release packaging are unchanged. `Windows acceptance / x64`
and `Windows acceptance / ARM64` have a 25-minute job limit and upload reports,
executable identities, target observations and logs even after a failed test.
The separate [TestISP proof](testisp/README.md) runs before the harness is
accepted as evidence.

## What counts as evidence

- Both public egress baselines use verified `1.1.1.1` HTTPS before app tests.
  Physical failover and main-line cap exceptions retain `1.0.0.1:443`.
  Pin changes, combining and TestISP failback use local TLS through a single
  non-final destination rewrite, retaining process rules and interface binding.
  The native probe must reach the rewrite's exact address and port, fail at
  connect time as unreachable when TestISP's default route is withdrawn,
  without reaching the responder, and recover after restoration. It binds the
  source address and `IP_UNICAST_IF`, while the product binds the interface
  only; the exact TestISP destination counts below show the engine's own flows
  crossed TestISP. No route to the TLS target is added. Physical selection in the
  local cases proves engine binding and TestISP +0, not physical egress; the
  retained public cases cover that. The response and TestISP's packet,
  byte, connection and destination counters distinguish the two paths.
  Its TestISP destination count must change by exactly the expected number:
  all pinned TestISP flows, zero main/failover flows, and the secondary share
  reported while combining.
- Controlled HTTP reports the source address and port it saw, and echoes a
  random request nonce. UDP must return the exact bytes sent. STUN checks the
  mapped port at two responders and a reply from a third, uncontacted port.
- QUIC v1 uses a local target, a per-run pinned certificate and a 1 MiB payload
  hash. The additional `quic-go` dependency is MIT and test-only; the production
  app does not import it.
- Old connections must keep using their original sockets. Reconnecting behind
  the test's back is a failure, even when the new request succeeds.
- The 100 MB body is a per-request AES-CTR stream, checked with SHA-256. Its bytes
  vary by position, so duplicated or reordered chunks cannot hide in filler.
- Missing baselines fail CI. A broken target, process, control API or harness
  never becomes a `baseline-defect` exemption. Independent probes may continue
  collecting evidence after a failure; the job remains failed.

## Launch contract

The runner takes `--server-exe` (also `--server-executable`), optional
`--server-entry`, and `--engine-exe` (also `--engine-executable`).
Today acceptance selects Node, the test launcher for the shipped server factory,
and the pinned sing-box binary. A native
server omits `--server-entry`. Version commands can be supplied as JSON arrays
with `--server-version-args` and `--engine-version-args`.

Each run records absolute paths, versions and SHA-256 hashes before starting.
The Node entry file is separately hashed. The running engine PID's executable
path is checked too, so passing a different engine cannot silently test the
bundled one. The current launch adapter uses `--user-data`, `--machine-data`,
`server.json` and `engine.pid`. Production Node entries use `--engine-dir`;
the Node e2e shim and Go control use the exact `--engine-executable` path.
Native control receives `--root` and defaults to `--version` for identification.
Service launch adapters belong to
milestone 2; traffic assertions use only the app API and observed packets.

`scripts/e2e-routing.mjs` uses the same launcher and retains its assertions.
`scripts/e2e-tun.mjs` retains its engine assertions with a real TestISP line and
mandatory controlled DNS probes. Startup and app choices go through the selected
Node or Go control service; selector checks still use the engine API directly.
Its identity record names the actual control binary and Node entry when used.
`acceptance.mjs` provides the broader packet-level acceptance suite.

The dedicated engine-config/TUN job passes `--engine-adapter`. That explicit
mode tests today's Node `Engine` directly and refuses a different control
executable; it never presents an adapter run as control-service coverage.
Its HTTPS peer is local, with a fresh certificate trusted only by the client.
One non-final destination rewrite leaves the real pins, selectors and bound
outbounds in charge. TestISP counters prove the bb path, and client port reuse
plus the responder's socket identity prove the original connections survive.
Control now uses that same local TLS peer and path assertions. The Node test
launcher intercepts only its engine-config write; Go's `control_test_https`
build uses the existing file-I/O seam. The normal Go binary contains no fixture
reader. Both save the original config and assert that the one non-final rule
and `log.level=info` are the entire difference. Startup and shutdown still belong to Control.
The marker is removed before all 20 ordinary lifecycle cycles.

Control sends one public trace request through the TUN on physical line aa,
with verified TLS and an engine record proving the app, source port and line.
Its preceding proxy-routing run uses `--public-via-tun` to avoid a second
public request. Standalone proxy-routing runs retain their one public request;
the direct engine-adapter TUN mode stays local. All held-socket assertions use
local TLS. This is a count of explicit test requests, not
the product's background line-health probes. See
[the target inventory](control-https-inventory.md) for those and the separate
acceptance/TestISP suites.

Before cleanup after a failure, Control TUN records fresh Control state,
independent 2.5-second engine API probes, two CPU/memory/thread samples of the
PID in `engine.pid`, Windows TCP rows and NetSwitch adapter counters. Client
request/connect/secureConnect timestamps and responder FIN/error/close events
join source ports to responder connection IDs. On bb, engine TCP rows show
TestISP relay ports, not the responder's `sourcePort`; join them using the
connection ID echoed in each reply. The traffic engine's info log
is printed on failure and saved with the artifacts; ordinary lifecycle runs
restore the product's warn log level.

## Classification

Pre-engine checks are `harness-baseline`, separate from engine `parity` passes.
Only a verified public TLS response with HTTP 5xx is `public target unavailable`.
Reset and early-close messages retain an unproven origin, endpoint and phase;
all still fail without retry. A health-vote deadline collects independent public
baseline evidence on both lines and explicitly leaves unmeasured endpoints
unattributed. Product health probes remain public and unchanged.
Engine cases are `parity` or `baseline-defect`. The latter needs a recognized
failure with a successful baseline and records its measured evidence. The
`baseline` profile reports such defects without failing the job; `v1` makes
them failures. Under `baseline`, a defect which no longer reproduces is
`defect-not-reproduced` and fails CI: review the executable pin and classification.
Only `v1` expects a former defect to pass.

DNS survival is deliberately `parity`, departing from the locked design's §10
defect list: the pinned sing-box 1.14.2 does not reproduce the DNS drop. The test
waits for Windows to report the changed DNS servers, then repeatedly refreshes
the original sockets and checks the engine PID through a 10-second observation
window. A future engine bump that drops them must fail, not gain an exemption.
Pins and combining wait for their returned/applied app state; caps and failover
wait for blocked and lane state. No fixed readiness sleeps remain in these cases.

Hosted x64 and ARM64 testing also found that today's app returns oversized UDP
despite the app requesting no fragmentation, on both IPv4 and IPv6. This extra
`baseline-defect` requires the direct DF baseline to reject the same size and the
TUN probe to return the full payload. A timeout is not exempted.

The strengthened reset probe also measured a sing-box 1.14.2 defect: it reports
FIN for a controlled upstream RST, while both native and TestISP paths report
`ECONNRESET`. Only that specific substitution is a `baseline-defect`; the
gateway's own reset preservation remains a mandatory baseline on both arches.

Immediate TCP reuse records Winsock bind retries separately. A `close` event can
arrive before Windows consumes the final ACK; the captured exchange showed a
complete passive close and `EADDRINUSE` before any new SYN. Only that failed bind
is retried, for at most 100 ms. Connected attempts and TCP timeouts are never
retried, and the recorded latency includes the bind wait. The physical-path
baseline performs 1,000 immediate reuses before the engine starts.

The native baseline keeps one client source port and rotates the responder's
listening port for each attempt. The old fixed-peer version intermittently timed
out before the engine started; a hosted state capture showed that exact tuple's
responder still in TIME_WAIT. Rotating only the native peer isolates client-side
source-port reuse from Windows' server-side TIME_WAIT policy. Both ports are
recorded and checked. TestISP and engine probes keep the entire tuple fixed, and
each successful reuse must complete in under 100 ms, excluding the requested
idle gap. Native failures still capture both ends' TCP states and fail CI.

TestISP installs the shared `tcp.SetTimeWaitHandler` before capture starts and
retains gVisor's default 60-second TIME_WAIT. Its fixed-tuple 1,000-reuse
prerequisite is mandatory: every attempt must finish under 100 ms. Engine freeze
gates require both it and the native baseline, including reuse after 100 MB.
The TestISP prerequisite runs four consecutive 1,000-reuse rounds to expose
intermittent relay delays. Each round keeps its tuple fixed; all four must pass.
The first slow or failed attempt stops the gate and retains its packet trace
and connection/data/FIN timing phases. There is no retry of a failed round.
Timeout zero was removed after a hosted ARM64 trace showed a lost final ACK,
then a retransmitted FIN receiving RST. Increasing bind retries would hide it.

Cap rejection has a mandatory closed-port baseline. Node's Windows libuv ignores
UDP refusal errors, so this probe uses a native socket and explicitly enables
`SIO_UDP_CONNRESET` after Go initializes it. The same executable must receive
exact UDP echoes before applying caps and after clearing them; a timeout cannot
be blamed on the app when the native refusal baseline failed.
TCP and UDP each use their own slowest native sample plus 500 ms as the rejection
deadline. TCP's roughly two-second refusal cannot grant UDP the same delay.
`ETIMEDOUT` is not a rejection. During the blocked burst, neither the
TCP target's flow counter nor the UDP target's datagram counter may increase.
The 0.3.x blocked flag acknowledges a written file, not sing-box's reload. The
baseline adapter therefore records canary outcomes until an actual prompt
refusal proves the rule is active, then snapshots counters and starts the burst.
The `v1` profile gets no canary grace: its applied-state contract acknowledges
the revision before the API reports it. This replaces the old fixed 500 ms wait.
An independent cap case holds flows on both lines: old secondary flows must
close while the exhausted main line, with no stand-in, keeps its original sockets.

Socket behavior is checked against Microsoft's [Winsock port reuse guidance](https://learn.microsoft.com/windows/win32/winsock/using-so-reuseaddr-and-so-exclusiveaddruse)
and [UDP IOCTL definitions](https://learn.microsoft.com/windows/win32/winsock/winsock-ioctls),
[RFC 1122 section 4.2.2.13](https://www.rfc-editor.org/rfc/rfc1122#section-4.2.2.13)
and [RFC 6191](https://www.rfc-editor.org/rfc/rfc6191) for TCP reuse, and
[RFC 8085 section 5](https://www.rfc-editor.org/rfc/rfc8085#section-5) for UDP's
lack of TIME_WAIT and the need to distinguish delayed packets. UDP probes use
fresh random payloads and record source tuples, so stale replies cannot pass.

| Area | Checks |
| --- | --- |
| Routing | Pins on both interfaces; existing sockets survive a new pin; combining; route-loss and gateway-drop failover and failback. |
| TCP freeze | Passive-close reuse at 0, 10, 100 and 500 ms; up to 1,000 immediate reuses; recovery after the 60-second interval; a 100 MB hash and reuse after it. |
| DNS | Held sockets before and after a real adapter DNS change, followed by restored DNS and a new connection. |
| Caps | Repeated TCP rejects, continuously sending UDP, no traffic escaping the block, and the exhausted main line remaining usable. |
| UDP | Exact payloads at 64, 1,200, 1,800, 8,192 and 12,000 bytes; fragmentation across the app's 9,000-byte TUN; STUN mapping and unsolicited replies. |
| QUIC | Real QUIC v1 handshake and 1 MiB payload hash through the TUN. |
| IPv6 and ICMP | Controlled IPv6 TCP/UDP; IPv4/IPv6 echo; 1,400-byte echo probes with wire counters; UDP with DF and oversize rejection on both families. |
| Lifecycle | Engine crash with automatic restart; abrupt control death followed by observed engine self-exit, unbound direct connectivity, then startup; 20 start/stop cycles with traffic and cleanup. |

## Design deviations and limits

Cleanup checks query the Net Plug and Play class without `-PresentOnly`, as well
as adapters, routes and firewall rules. Normal routing stops and both crash
cases snapshot non-present Wintun devices before another startup or TestISP
shutdown can sweep them away. Instance IDs are recorded while the app's device
is present. Only those owned IDs can become an intermittent `baseline-defect`
when non-present; absence is a parity pass. A new/present device or a route or
firewall leftover still fails, and all orphans fail the v1 profile.

This is also a normal-stop defect in 0.3.x, not just a crash consequence. In run
`39259073469`, ARM64 job `118081706767`, the first ordinary stop left a
`sing-tun Tunnel` PnP device after a 20-second wait, and it remained at final
cleanup. `lib/engine.mjs:530` calls `child.kill()` for a normal stop; Node's
[pinned Windows implementation](https://github.com/nodejs/node/blob/v24.21.0/deps/uv/src/win/process.c)
uses `TerminateProcess` for that signal. The harness calls the app API correctly.
The app needs graceful engine shutdown and owned-device recovery after crashes;
this acceptance branch records the defect without deleting its evidence.

TestISP is a separately observable virtual path sharing the real uplink, not a
physically separate uplink. Physical cable loss cannot be isolated on a runner
with one uplink. The proof uses a firewall rule scoped to the direct probe and
interface, leaving the gateway's uplink sockets and runner agent alive.

A local responder on the runner's private NIC address bypasses the app TUN. It
therefore has two addresses: that real NIC address for direct baselines, and
`198.19.128.2` translated by TestISP after crossing its adapter for TUN probes.
This is the same controlled responder, but the direct local address does not
prove real internet egress. Public HTTPS separately proves that on both lines.

IPv6 targets are synthetic: documentation-range addresses on the runner and
TestISP enable the app's existing IPv6 gate. `2001:db8:198::2` is translated to
the controlled responder. This proves IPv6 capture and forwarding on TestISP;
it is not evidence of public IPv6 connectivity on the hosted NIC. ICMP echo is
served only for the controlled addresses. The gateway never fabricates echo
replies for arbitrary internet hosts. The test UDP allowances are restricted
to the participating programs and controlled source addresses, then removed.
During engine checks, outbound firewall rules block the client, MTU, QUIC, ping
and UDP-rejection probes on both TestISP and the uplink. Engine sockets remain
allowed. Pre-engine negative controls prove IPv6 UDP, echo and MTU probes cannot
reach the target through TestISP's remaining IPv6 default route.
Windows' ICMP API can bypass the program firewall rule. IPv6 ping therefore also
requires Windows' selected source interface to be NetSwitch and passes that
address explicitly with `-S`. MTU probes independently reject a direct TestISP
source address in their socket report.

The socket client cannot inject app-side TCP sequence numbers, stale SYN/data/RST,
lost final ACKs, disabled timestamps or reordered TUN queues through Winsock.
Those freeze gates remain explicitly deferred to milestone 3's in-memory engine
link endpoint. They do not count as passes here. Service lifecycle, lease,
worker, migration, update/rollback and uninstall placeholders name milestones
2 and 5. Existing installer smoke tests stay required.

## Local checks

`check-local.ps1` uses Go from PATH or `-Go`, checks the repository's pinned
version, and runs at Idle priority with two cores. It inherits Go's normal cache
settings (overridable through the standard environment variables). It supports
`vendor`, `verify`, `vet` and `build`; it never runs tests or either program's main.
The report classification tests are `test/windows-acceptance.test.mjs`.
