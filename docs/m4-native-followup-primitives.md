# Native follow-up primitives (M4, PR 1b)

These contracts prepare the native engine for Control's cutover. The installed
service still hosts the engine in process. The supervisor/child separation
recorded in the spec belongs to PR 1c.

| Contract | Behavior | Hosted proof |
| --- | --- | --- |
| Probes | Explicit `target`, `quick`, `custom`; custom HTTPS HEAD with normal certificate checks | Real installed service, private TLS fixture, invalid certificate and local socket exhaustion |
| Test proxy | Test-build-only loopback HTTP CONNECT and SOCKS5 TCP | Product refuses activation and opens no listener; test build forwards and survives capacity exhaustion |
| Missing lines | Saved unplugged selectors are valid; the supplied lane selects a live line | Cold service start with an absent main line and working fallback |
| Line churn | Retire unused selectors and safely reuse Linux routing slots | 300 line identities in one instance while an old flow stays on its original physical path |
| Status and snapshots | Separate totals slots; adapter-loss error persists; retained Linux exits belong to the current boot | Existing installed outcome/transport proofs plus focused unit tests |

## Probe wire contract

The fenced, idempotent `probe` request accepts `line`, `target` (literal IP:port),
`quick`, and `custom`, alongside its `opId`, epoch and instance. Existing named
`operator` requests remain supported; supplying both operator and target fails.
The legacy `operator: "IP:port"` shorthand (also with `quick:`) is deliberately
rejected. Custom callers must send `target` and explicit `quick`/`custom` options.
`hello` advertises `probe-options` when supported.

Quick checks complete a bound TCP connect within three seconds. Full checks use
the existing Control response rules in `internal/linecheck`, with a ten-second
bound. Custom targets use HEAD, accept any HTTP response status, and never follow
redirects. Named targets keep their GET paths and operator-specific validation.
Local socket/resource exhaustion returns `engineUnavailable`; remote refusal,
TLS errors and network timeouts return `lineFailed`. Linux `EADDRNOTAVAIL` counts
as ephemeral-port exhaustion only while the latest published binding has both a
default route and a usable source address of the target family. Missing routes,
missing sources and failed duplicate-address detection are line failures; the
route monitor refreshes that evidence every second.

Every completed result includes `kind: "quick" | "full"`, including failures and
engine-unavailable results. Successful latency is `latencyMs`, a fractional
millisecond value; failures omit it. No duration in nanoseconds goes over IPC.
**PR 2 integration:** Control must require the expected kind before accepting a
result (quick never restores a line requiring full HTTPS), and drop a delayed
result if its originating engine instance is no longer current. Both checks are
in Control since [the production cutover](m4-production-cutover.md).

Harness caller audit: Windows capacity probes its plain TCP echo peer with
`target, quick:true, custom:true`. Windows driver health and Linux's binding
case use explicit quick TCP checks; their HTTPS validation/recovery cases use
`quick:false, custom:false` to keep the named endpoints' response rules. The
Linux session accepts a typed request and rejects a mismatched result kind.
TestISP's CLI probe independently performs verified HTTPS, while capacity-client
probes are direct TCP exchanges; neither sends an engine protocol request.
Only the deliberate rejection tests still send an IP address as `operator`.

The real Go transport detaches dial deadlines to support connection reuse. The
probe explicitly retains its own deadline and cancellation on that dial, so a
cancelled request cannot leave an unbounded socket attempt behind. Test CA and
one-shot exhaustion injection exist only in the lifecycle fault build.

## Test proxy boundary and budgets

The authenticated engine protocol exposes `testProxy {opId, listen}` in test
builds (`lifecycle_test` or `acceptance`). Product builds compile a disabled stub;
neither an environment variable nor an IPC request can enable a listener.
No route or capture configuration points at this listener. Both its bind address
and its clients must be loopback. Proxy destinations cannot be loopback or
unspecified, preventing recursion. Domain targets use the ordinary OS resolver;
there is no DNS interception.

There are at most 64 connections, reserved before handshake goroutines start.
Headers are bounded to 8 KiB, the handshake to five seconds, setup to ten seconds,
and a relayed connection to two minutes. Two 16 KiB buffers per relay reserve at
most 2 MiB. SOCKS supports no-auth TCP CONNECT only. Half-close and shutdown join
all relay workers. The real client's socket tuple supplies attribution; the
request cannot supply an app identity. Policy, lanes, flow listing, closure and
accounting use the same flow table as TUN traffic. Destination address family
controls IPv6 policy even when the proxy transport is IPv4 loopback.

## Line retention and accounting

A Linux slot remains reserved while a line is configured, a resolved admission
uses it, or a TCP/UDP/ICMP/probe socket holds it. Retirement tombstones the old
published binding, deletes journaled selectors before routes, and only then
permits slot reuse. A failed reconciliation retains that deletion barrier.
Allocation rotates through all 255 slots. Any slot used by a socket also stays
unavailable for at least 60 seconds after its latest userspace close, covering
ordinary kernel FIN/retransmission tails. This is a reuse floor, not a claim that
every kernel tail ends within 60 seconds. Unused configuration-only slots do not
need that delay. Exhaustion returns a retryable diagnostic when all slots are
occupied or cooling down; it never requires restarting. App-facing TIME_WAIT
accounting alone does not keep a physical binding alive.
Windows retains removed selectors while live admissions need physical-loss
monitoring, then prunes them. Aggregate status reports configured bindings only,
from an immutable published snapshot. Neither bindings nor TUN counters wait on
the route monitor's adapter/firewall lock.

Flow listings and totals each have four snapshot slots. Totals may use at most
half the existing aggregate snapshot-byte budget, leaving room for maximum-size
flow listings. Ten-second expiry releases reservations without discarding any
unacknowledged accounting. A fresh full totals read replaces the current
controller's oldest snapshot when a slot or byte limit would otherwise prevent
it. Reattach drops the fenced controller's snapshots immediately. Superseded
cursors and receipts fail explicitly; counters and generations stay intact for
the next full read. Only an exact, completed acknowledgement retires accounting.

The shared disposable-account helper also checks the actual Windows logon token
is unelevated and has no linked elevated token. It also allows only the five
standard-user token privileges (change-notify, shutdown, undock, working-set and
time-zone), whether enabled or disabled. This check applies with UAC on or off;
direct debug/backup or other admin rights fail independently of elevation type.
The Linux helper checks the root-side
`sudo -n -l -U` result for an explicit no-commands outcome. Both lifecycle suites
use these checks. Linux outcome records include the kernel boot ID; a previous
boot's clean result cannot become the current service's exit status.

## Validation boundaries

Pure tests cover response parity, cancellation bounds, classified errors,
coalesced proxy payloads, policy denial, capacity, exact counters, slot races,
snapshot isolation, account criteria and stale boot records. Local validation
uses only pure tests and cross-builds. Hosted native-service jobs exercise both
product and fault builds through SCM/systemd on Windows x64/ARM64 and Linux
x64/ARM64. They log request methods, churn duration and the existing cleanup and
stall evidence. The watchdog and Linux attribution release gate remain separate
work.

References used for contracts: [SOCKS5](https://www.rfc-editor.org/rfc/rfc1928.html),
[HTTP CONNECT](https://www.rfc-editor.org/rfc/rfc9110.html#section-9.3.6),
[Windows token elevation types](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ne-winnt-token_elevation_type),
[sudo command listing](https://github.com/sudo-project/sudo/blob/main/plugins/sudoers/display.c),
and [sudo-rs command listing](https://github.com/trifectatechfoundation/sudo-rs/blob/main/src/sudo/pipeline/list.rs).
Kernel references: [connect errors](https://man7.org/linux/man-pages/man2/connect.2.html),
[TCP close timers](https://www.kernel.org/doc/html/latest/networking/ip-sysctl.html),
and [IPv6 retransmit routing retains the socket mark and bound interface](https://github.com/torvalds/linux/blob/master/net/ipv6/inet6_connection_sock.c).
Windows token rights: [privilege constants](https://learn.microsoft.com/en-us/windows/win32/secauthz/privilege-constants).
