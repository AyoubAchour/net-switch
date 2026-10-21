# TestISP

The gateway keeps gVisor's default 60-second TIME_WAIT and installs the shared
section 5.1 SYN-reopen hook before starting capture. Both the physical-path
baseline and 1,000 fixed-tuple TestISP reuses are mandatory. Every TestISP reuse
must complete in under 100 ms. Timeout zero is unsafe and is not used.

TestISP is a separately observable virtual path sharing the runner's real uplink.
It is not a physically separate uplink. Run it only on disposable GitHub-hosted
Windows runners, never on a developer's PC or a self-hosted runner.

The signed, unmodified Wintun DLL is fetched only in CI using
`packaging/versions.json` → `nativeSources.wintun`. Both the archive and the
architecture's DLL are verified, together with the Authenticode signature.

The host owns `198.19.0.1/30` on TestISP. This benchmark range is outside the app's
`LOCAL_RANGES`, and does not overlap its `198.18.0.1/30` TUN. A high-metric on-link
default makes TestISP a selectable line without replacing the runner's uplink.
gVisor terminates its TCP and UDP traffic. Every relay socket binds both the real
uplink address and `IP_UNICAST_IF`; IPv4 uses the network-byte-order interface
index required by Winsock. A route chosen by metric alone is never sufficient.

The acceptance extension uses one unconnected UDP socket per source address and
port. It preserves mappings across destinations and relays unsolicited replies.
IPv4/IPv6 reply construction and fragmentation have pure unit tests. Controlled
target translation is configured over the control API; it never translates
arbitrary public destinations. See the [acceptance limits](../README.md).

The loopback control API exposes packet, byte, connection and destination counts
for TestISP and its upstream relay. It supports `running`, `pause` (stop reading
the adapter), and `drop` (drain and discard packets). The proof also withdraws and
restores TestISP's default route. Shutdown closes the adapter, and the runner
script verifies no adapter, routes or non-present PnP devices remain. After the
gateway exits, a fresh process calls `internal/wintun.RecoverAfterCrash` with
TestISP's own fixed GUID. It refuses present adapters and never loads the DLL.

`proof.mjs` keeps public HTTPS baselines on both explicitly bound interfaces.
Pause, drop, withdrawal and TestISP recovery use the same local TLS endpoint.
Before those cases, the bound probe to that endpoint's address and port must
fail at connect time as unreachable (WSAENETUNREACH or WSAEHOSTUNREACH, not a
timeout) with TestISP's default route withdrawn, and recover on restoration;
the withdrawal case below checks the same failure. Counters and responder nonces prove
the path. No host route is added. The direct path still uses public HTTPS: its
assertion means physical egress, which a same-runner responder cannot prove.
A process-and-interface-scoped firewall rule then stops only the direct probe.
The unaffected TestISP probe in that case stays public too: it checks isolation
between two programs sharing the real uplink, so the gateway must still cross
that uplink, which a local relay delivered on the runner would not show. These are
software failure domains sharing one real uplink. The proof checks actual packet
counters; two outbound labels or identical public source IPs are not evidence.
In drop mode the zero-change destination counter proves nothing: discard happens
before counting. The successful direct connection is the evidence of failover.

## Reuse investigation

Dispatch `ci.yml` on this branch to run only the dedicated TestISP investigation:
10 fresh hosted machines per architecture, each measuring 10 rounds of 1,000
fixed-tuple reuses. It does not run the app and is not a required PR check.
Every slow attempt is saved before continuing; no round is retried and any
attempt at or above 100 ms makes that job fail. Normal CI still stops its
mandatory gate at the first slow attempt.

Round artifacts include gVisor TCP counters, Windows IPv4 TCP retransmits,
Wintun session drops, recoveries and NDIS discards, header traces, forwarder/hook/dial/
handshake/first-byte/close timestamps, observed endpoint states, GC pauses,
and independent 1 ms gateway/client heartbeats. Gaps over 5 ms retain both ends
of the interval. Endpoint states are sampled at packet and relay boundaries and
each heartbeat; transitions between observations can be missed. Windows TCP
counters cover the whole host, so a change alone cannot attribute a lost packet.

The gateway uses the shared `internal/wintun` session with the same 8 MiB rings.
Its batch API reports the accepted packet count; a dropped packet cannot be
reported as delivered. No packet is retried by the gateway wrapper.

Set the dispatch input `packet_capture=true` for three additional runners per
architecture with Windows Packet Monitor. This records the NIC and TCP/IP
arrival times, packet checksums and drop reasons. Capture is diagnostic only;
it leaves the 100 ms gate unchanged.

### Wintun wake-up race, measured 2026-10-19

Run `39255636353`, ARM64 job `118070104194`, round 1 attempt 104 took 344.41 ms.
Connect took 0.87 ms and first data 1.50 ms. The gateway submitted FIN sequence
128541580 at 13:03:26.520292 UTC, then retransmitted at 13:03:26.862966.
Packet Monitor saw both FINs reach TestISP's NIC at 13:03:26.8631337 and
13:03:26.8632408, only 107 microseconds apart. It reported **no events lost**.
Both packets had valid IP/TCP checksums. gVisor retransmits increased by one;
its timeout counter, Windows retransmits and Wintun/NDIS drop/error counters
did not change. Neither heartbeat had a gap matching the stall. Round 2 attempt
163 showed the same queued-packet pair (339.87 ms).

This matches Wintun 0.14.1's missed wake-up in the receive-ring Alertable/Tail
handshake. The producer and consumer can both see stale state and leave the
driver asleep until another packet signals it. Upstream fixed both store/load
ordering points in [commit ec0a6b9](https://git.zx2c4.com/wintun/commit/?id=ec0a6b98456fe1ba52567bb2add4bbf5f64315a1):
`api/session.c` in `WintunSendPacket` and `driver/wintun.c` in
`TunProcessReceiveData`. The [official signed download](https://www.wintun.net/)
and [latest release tag](https://git.zx2c4.com/wintun/refs/tags) are still 0.14.1
as of the measurement date; that release lacks the fix.

The gateway now uses our ring session from PR #35. It signals the driver's
auto-reset wake event after every published batch, so the driver cannot miss a
wake-up even with the unchanged signed 0.14.1 driver. The DLL manages adapters
only. The old DLL session and polling wrapper are removed. The mandatory gate
still has the same 100 ms deadline and no noise allowance or round retries.
Per-job attempt counts and the packet/counter evidence are retained in
[reuse-investigation.json](reuse-investigation.json), including incomplete rounds.
PR #33 was merged and vendor regenerated before the second stress run
(`39254207549`); the FIN stalls still reproduced. Its SYN handoff change cannot
explain these cases: the handshake already finished in under 2 ms. A lost SYN
or SYN-ACK would instead exercise the handshake retransmission timer (gVisor's
initial value is one second). The captured Windows TCP templates also use an
initial RTO of 1,000 ms. Neither is this established-connection FIN recovery.

`testisp-probe.exe` is the same source and binary as the gateway, launched in
`probe` mode under a separate executable path so firewall rules can distinguish
the processes. It uses native Winsock HTTP sockets, not the gateway's gVisor
data path; it is not an independently implemented executable.

gVisor is vendored under Apache-2.0. The session is our own code; the signed DLL
retains its prebuilt-binary license. The gateway remains test infrastructure.
