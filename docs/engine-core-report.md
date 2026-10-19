# Routing core handoff

19 October 2026. Milestone 3, part 1: the platform-independent engine is implemented.
This does not replace the running 0.3.x application. Nothing has been merged or tagged.
The immediate TCP reuse gate is **not passed**.

## Review units

| PR | Scope | Dependency |
|---|---|---|
| [20](https://github.com/AyoubAchour/net-switch/pull/20) | Vendored dependencies, interfaces, stack, link queue, TIME_WAIT gate | main |
| [22](https://github.com/AyoubAchour/net-switch/pull/22) | TCP admission, bound dialing, half-close relay | 20 |
| [23](https://github.com/AyoubAchour/net-switch/pull/23) | UDP NAT, validation, replies, socket identity | 22 |
| [26](https://github.com/AyoubAchour/net-switch/pull/26) | Policy, budgets, flow accounting, protocol, runtime wiring | 23 |
| [27](https://github.com/AyoubAchour/net-switch/pull/27) | Durable ownership journal and crash recovery | main, independent |
| [29](https://github.com/AyoubAchour/net-switch/pull/29) | Fuzzing and combined regression coverage | 26 and 27 |

All target main as requested. Dependent branches include their prerequisites, so their
diffs are cumulative until those prerequisites land. The journal is also included in
the final branch to test the assembled core. Fixes were propagated to the affected PRs.

## Must resolve before shipping

**TIME_WAIT=0 is unsafe on the pinned gVisor.**

- **Now:** losing the final ACK produces a reset while the app is in LAST_ACK.
- **Now:** old data can enter a new connection with overlapping sequence numbers and no timestamps.
- **Should:** immediate reuse must preserve both connection state and payload integrity.

The safe 60-second timeout remains enabled. No gVisor patch is carried. The proposed
RFC 6191 alternative needs separate approval and review. Until it passes the complete
gate, immediate reuse remains a release blocker; the longer timeout also retains
netstack TIME_WAIT metadata beyond the active flow's lifetime.

The tests named `TestTimeWaitCandidateFails*` assert these reproductions. A passing
test means the unsafe behavior was reproduced, **not that timeout zero is accepted**.
See [the gate findings](engine-timewait.md) for the exact cases.

## Validation

Local checks use Go 1.27.2, the vendored dependencies, two workers and Idle priority.
The short suite and vet pass across the named `internal`, `cmd` and `tests` trees.
Local tests create no adapters, routes, firewall rules or services.

CI runs full tests and builds on Windows/Linux, amd64/arm64. Race detection runs on
Linux amd64/arm64 and Windows amd64. The ordinary test run prints every test name and
duration on the combined branch; the TIME_WAIT gate also has a separate verbose run.
Full 100 MB hash checks run in CI, including the TCP relay and reuse gate.

The final PR runs three fuzz targets for 30 seconds each with two workers on Linux
amd64: packet parsing/replies, the UDP hook, and protocol decoding/dispatch.
Seeds run on every architecture. Final CI results are recorded on the linked PRs;
green status alone must not be read as passing the rejected TIME_WAIT candidate.

The [Linux amd64 log for f045d62](https://github.com/AyoubAchour/net-switch/actions/runs/39218678474/job/117948556500)
confirms all seven TIME_WAIT tests ran: 1,000 reuses per timestamp mode, a 0.49-second
100 MB gate, and both explicit `GATE FAILED` reproductions. Its fuzz runs executed
1,954,983 packet cases, 795,145 UDP cases and 256,239 protocol cases in 30–31 seconds
each. Final regression additions run again on the latest PR head.

Coverage includes concurrent first UDP packets, unsolicited replies, reordered IPv4
fragments, maximum-MTU replies, changed owners with opposite/blocked pins under
continuous traffic, missed/late destroy events, stalled identity reconciliation,
every admission limit, persistent totals, lane changes, revisions, closure cutoffs,
slow control readers, lease fencing, and ten journal crash boundaries.

The vendored source files match the verified module cache. The upstream gVisor license
gained a final newline; its text is unchanged. `go mod verify` passed. Dependencies and
notices are committed, with no copied GPL/LGPL implementation code.

## Next task: platform contracts

The next implementation supplies these interfaces from `internal/engine/platform`:

- **TunDevice:** MTU 9000, cancellation-aware packet reads/writes, and Close that unblocks I/O.
- **LineDialer / TCPConn / UDPConn:** bound sockets only, half-close, full datagrams and path-MTU errors; never retry unbound. Close must unblock pending I/O.
- **OwnerLookup:** TCP tuple or UDP local endpoint to PID, process start, path, app identity and socket generation.
- **UDPIdentity:** complete snapshots; absence means gone, incomplete dumps return errors. Feed generation-matched destroy events and refresh after notification loss/restart.
- **RouteManager:** journaled, transactional Prepare; preserve old-flow routes during apply; enable capture last; fingerprint-only, idempotent cleanup.
- **Prober:** line-bound health checks for the requested operator.

UDP without a verifiable generation is rejected. An unknown app still works when its
socket generation is known. The periodic hook and two-second stop-forwarding rule are
tested with fakes; the one-second real Windows/Linux attribution bound needs OS tests.

For `internal/journal`, supply the named mutex/flock, per-kind object drivers and the
directory durability hook. Hold the journal session lock for the engine's lifetime;
recover old objects before new startup, and compare the full fingerprint again inside
Remove. Create the journal/state directories with the specified ACLs or modes.

Serve JSON lines over authenticated pipes/sockets. Start one `Server.RunLease` loop
under the engine's lifetime context; it handles expiry and forwards queued events.
The control client renews every five seconds. Connect platform line-down/address-loss
notifications to the existing flow selectors; policy lane changes alone do not close flows.

`netswitch-engine version` is the only runnable command for now. Privileged TUN routing,
real socket binding, OS lookup, ICMP echo, service installation, the test proxy and the
cross-platform end-to-end harness are outside this part and remain unimplemented.

## Remaining validation limits

The tests exercise the core through gVisor channel endpoints and fake egress sockets.
They do not establish real-network throughput, QUIC/STUN interoperability, OS crash
durability or sustained RSS. The later platform and soak gates still apply.
Totals remain cumulative for the engine instance; unusually many distinct app identities
can exceed the protocol's single-message limit and currently return a size error.
No journal compaction is implemented in this part.
