# TestISP

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

Dependencies are vendored from upstream MIT (WireGuard/Wintun) and Apache-2.0
(gVisor) sources. The gateway is test infrastructure, not the production engine.
