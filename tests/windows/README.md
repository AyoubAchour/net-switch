# Windows acceptance

These programs run only on disposable GitHub-hosted Windows runners. Do not run
the gateway, clients, server, engine or PowerShell network scripts on a developer's
PC. Local checks are syntax, vet and the pure report/packet unit tests only.

The existing app and release packaging are unchanged. `Windows acceptance / x64`
and `Windows acceptance / ARM64` have a 25-minute job limit and upload reports,
executable identities, target observations and logs even after a failed test.
The independent [TestISP proof](testisp/README.md) runs before the harness is
accepted as evidence.

## What counts as evidence

- Real internet routing uses a small HTTPS response from `1.1.1.1`. Both bound
  paths must work before app tests start. The response and TestISP's packet,
  byte, connection and destination counters distinguish the two paths.
- Controlled HTTP reports the source address and port it saw, and echoes a
  random request nonce. UDP must return the exact bytes sent. STUN checks the
  mapped port at two responders and a reply from a third, uncontacted port.
- QUIC v1 uses a local target, a per-run pinned certificate and a 1 MiB payload
  hash. The additional `quic-go` dependency is MIT and test-only; the production
  app does not import it.
- Old connections must keep using their original sockets. Reconnecting behind
  the test's back is a failure, even when the new request succeeds.
- Missing baselines fail CI. A broken target, process, control API or harness
  never becomes a `baseline-defect` exemption. Independent probes may continue
  collecting evidence after a failure; the job remains failed.

## Launch contract

The runner takes `--server-exe`, optional `--server-entry`, and `--engine-exe`.
Today these select Node, `server.mjs` and the pinned sing-box binary. A native
server omits `--server-entry`. Version commands can be supplied as JSON arrays
with `--server-version-args` and `--engine-version-args`.

Each run records absolute paths, versions and SHA-256 hashes before starting.
The Node entry file is separately hashed. The running engine PID's executable
path is checked too, so passing a different engine cannot silently test the
bundled one. The current launch adapter uses `--user-data`, `--machine-data`,
`--engine-dir`, `server.json` and `engine.pid`. Service launch adapters belong to
milestone 2; traffic assertions use only the app API and observed packets.

`scripts/e2e-routing.mjs` uses the same launcher and retains its assertions.
`scripts/e2e-tun.mjs` retains its direct `Engine` adapter assertions, now with a
real TestISP line and mandatory controlled DNS probes. It explicitly refuses a
different control executable and names itself as the driver in its identity
record. Use `acceptance.mjs` for control-executable comparisons; the historical
direct-adapter test must not pretend to test a Go control server.

## Classification

Every active case is `parity` or `baseline-defect`. The latter needs a recognized
failure with a successful baseline and records its measured evidence. The
`baseline` profile reports such defects without failing the job; `v1` makes
them failures. A defect which no longer reproduces is reported as a pass.

Hosted x64 and ARM64 testing also found that today's app returns oversized UDP
despite the app requesting no fragmentation, on both IPv4 and IPv6. This extra
`baseline-defect` requires the direct DF baseline to reject the same size and the
TUN probe to return the full payload. A timeout is not exempted.

Immediate TCP reuse records Winsock bind retries separately. A `close` event can
arrive before Windows consumes the final ACK; the captured exchange showed a
complete passive close and `EADDRINUSE` before any new SYN. Only that failed bind
is retried, for at most 100 ms. Connected attempts and TCP timeouts are never
retried, and the recorded latency includes the bind wait. Both the physical and
TestISP baselines perform 1,000 immediate reuses before the engine starts.

| Area | Checks |
| --- | --- |
| Routing | Pins on both interfaces; existing sockets survive a new pin; combining; route-loss failover and failback. |
| TCP freeze | Passive-close reuse at 0, 10, 100 and 500 ms; up to 1,000 immediate reuses; recovery after the 60-second interval; a 100 MB hash and reuse after it. |
| DNS | Held sockets before and after a real adapter DNS change, followed by restored DNS and a new connection. |
| Caps | Repeated TCP rejects, continuously sending UDP, no traffic escaping the block, and the exhausted main line remaining usable. |
| UDP | Exact payloads at 64, 1,200, 1,800 and 8,192 bytes; fragmentation; STUN mapping and unsolicited replies. |
| QUIC | Real QUIC v1 handshake and 1 MiB payload hash through the TUN. |
| IPv6 and ICMP | Controlled IPv6 TCP/UDP; IPv4/IPv6 echo; 1,400-byte echo probes with wire counters; UDP with DF and oversize rejection on both families. |
| Lifecycle | Engine crash with automatic restart; abrupt control and engine death without restart, direct connectivity, then startup; 20 start/stop cycles with traffic and cleanup. |

## Design deviations and limits

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

The socket client cannot inject app-side TCP sequence numbers, stale SYN/data/RST,
lost final ACKs, disabled timestamps or reordered TUN queues through Winsock.
Those freeze gates remain explicitly deferred to milestone 3's in-memory engine
link endpoint. They do not count as passes here. Service lifecycle, lease,
worker, migration, update/rollback and uninstall placeholders name milestones
2 and 5. Existing installer smoke tests stay required.

## Local checks

`check-local.ps1` invokes only the pinned absolute Go toolchain, at Idle priority,
with two cores and caches below the owner's designated cache directory. Its
`unit` action runs only pure packet tests; it never calls either program's main.
The report classification tests are `test/windows-acceptance.test.mjs`.
