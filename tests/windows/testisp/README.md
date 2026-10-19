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
script verifies no adapter or routes remain.

`proof.mjs` proves an HTTPS response on each explicitly bound interface, then
proves the virtual path stops when paused, dropped or unrouted while the direct
path still works. A process-and-interface-scoped firewall rule then stops only
the direct probe; the gateway process can still relay TestISP traffic. These are
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
Wintun ring-full errors and NDIS discards, header traces, forwarder/hook/dial/
handshake/first-byte/close timestamps, observed endpoint states, GC pauses,
and independent 1 ms gateway/client heartbeats. Gaps over 5 ms retain both ends
of the interval. Endpoint states are sampled at packet and relay boundaries and
each heartbeat; transitions between observations can be missed. Windows TCP
counters cover the whole host, so a change alone cannot attribute a lost packet.

The gateway uses Wintun's documented session API with the same 8 MiB rings.
This exposes `ERROR_BUFFER_OVERFLOW`, which the former WireGuard wrapper
silently reported as a successful write. No packet is retried by this wrapper.

`testisp-probe.exe` is the same source and binary as the gateway, launched in
`probe` mode under a separate executable path so firewall rules can distinguish
the processes. It uses native Winsock HTTP sockets, not the gateway's gVisor
data path; it is not an independently implemented executable.

Dependencies are vendored from upstream MIT (WireGuard/Wintun) and Apache-2.0
(gVisor) sources. The gateway is test infrastructure, not the production engine.
