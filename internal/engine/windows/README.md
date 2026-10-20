# Windows engine platform

This package is the Windows data-plane boundary. The standalone process exposes
the production protocol over the protected engine pipe. The default pipe allows
SYSTEM; `--standalone-admin` additionally allows elevated administrators for the
hosted acceptance controller. Neither mode accepts a remote or ordinary-user
client. Services, enrolment and desktop IPC belong to milestone 2.

The engine holds its journal mutex on one locked OS thread for its entire
lifetime. Recovery runs under that lock, before any Wintun DLL load. It calls
the existing `RecoverAfterCrash` only for the name/GUID in a durable adapter
record. Live foreign adapters are never adopted. Interface configuration,
addresses and routes have durable intents and full live identity checks. The
capture-route phase persists all intents in one group commit before creating any
route, then persists the created marks together. Cleanup checks each fingerprint
in reverse order and commits removed marks together; durable intents recover any
interrupted phase. Physical defaults and interface metrics are left alone.

Owner snapshots use the all-state TCP table and the module-owner UDP table.
UDP's creation timestamp is part of its generation; PID alone cannot identify a
reopened socket. Lookup histograms are exposed by `stats`. A failed or incomplete
UDP dump cannot renew the NAT's two-second validation bound.

All socket creation sets the per-family interface option and binds the source
address. A failed binding never falls back to an unbound socket. Discovery keeps
virtual interfaces eligible so VPN-as-a-line policy can be added independently.

The Wintun session already preserves packet order and reopens corrupt rings.
The engine uses batch writes and checksum-verification metadata. Interface-down
events do not close a Wintun session; its final removal error fails the engine
open, and a fresh process rebuilds the adapter.

The temporary shared protocol and echo hooks match PR #36. The Windows readiness
backend targets that PR's shared TCP relay; there is no second relay design.

## Short-interval clock audit

The pinned Go runtime reads Windows' coarse interrupt clock in `time.Now`.
The same 500 cold ARM64 lookups measured p95 5.612 ms there but 1.504 ms with
`QueryPerformanceCounter`; 292 Go-clock durations were exactly zero. The gate
keeps both measurements and applies its unchanged 5 ms limit to QPC.

| Path | Timing decision |
| --- | --- |
| Owner retries | Two retries with a precise minimum 2 ms wait. The 50 ms private timeout and final result check use QPC; parent cancellation still wins. |
| TCP snapshots | QPC publication age expires at 5 ms. Atomic single-flight ownership and cancellation do not depend on a clock tick. |
| Backpressured TCP writes | QPC checks each 2 ms poll wait; a queued coarse timer wake cannot cause immediate repeated polling. |
| UDP read errors | Windows' 1 ms retry helper uses the same precise wait. The other-platform helper retains the original timer behavior. |
| Wintun registration/release | Registration backoff starts at 10 ms. Release polls at 1 ms with a precise 250 ms deadline. The deliberate first recovery attempt remains immediate. |
| Netstack | Windows supplies QPC monotonic time and precise timers with the specified 500 µs resolution. Wall-clock timestamps and long idle checks retain ordinary time. |
| UDP receive cancellation | `SetReadDeadline(time.Now())` deliberately sets an immediate/past deadline; it is not used as a positive short wait. |
| Native ICMP | The OS takes a positive relative millisecond timeout, bounded by the caller; cancellation interrupts the wait. |

The fake scheduler tests dispatch early wakes and callbacks from stopped
generations, while precise time advances independently. They verify positive
rescheduling, exact expiry, cancellation and reset. Snapshot tests cross the
5 ms boundary within one simulated 16 ms coarse tick. Hosted tests also measure
1/2/5/10 ms waits with QPC and reject every early return. No ownership-journal
operation runs on a packet or flow path.

## Reference study

These sources informed the API and lifecycle choices. No external source code
was copied or adapted.

- [Microsoft TCP owner tables](https://learn.microsoft.com/windows/win32/api/iphlpapi/nf-iphlpapi-getextendedtcptable)
- [Microsoft high-resolution interval timing](https://learn.microsoft.com/windows/win32/sysinfo/acquiring-high-resolution-time-stamps)
- [Microsoft UDP creation timestamps](https://learn.microsoft.com/windows/win32/api/udpmib/ns-udpmib-mib_udprow_owner_module)
- [Winsock interface binding and fragmentation options](https://learn.microsoft.com/windows/win32/winsock/ipproto-ip-socket-options)
- [IP Helper route creation](https://learn.microsoft.com/windows/win32/api/netioapi/nf-netioapi-createipforwardentry2)
- [IP Helper interface configuration](https://learn.microsoft.com/windows/win32/api/netioapi/nf-netioapi-setipinterfaceentry)
- [Per-interface DNS settings](https://learn.microsoft.com/windows/win32/api/netioapi/ns-netioapi-dns_interface_settings)
- [Named-pipe access checks](https://learn.microsoft.com/windows/win32/ipc/named-pipe-security-and-access-rights)
- [Windows ICMPv4](https://learn.microsoft.com/windows/win32/api/icmpapi/nf-icmpapi-icmpsendecho2ex) and [ICMPv6](https://learn.microsoft.com/windows/win32/api/icmpapi/nf-icmpapi-icmp6sendecho2)
- [wireguard-go Windows TUN](https://git.zx2c4.com/wireguard-go/tree/tun/tun_windows.go)
- [Tailscale Windows router](https://github.com/tailscale/tailscale/blob/main/wgengine/router/osrouter/router_windows.go) and [interface configuration](https://github.com/tailscale/tailscale/blob/main/wgengine/router/osrouter/ifconfig_windows.go)
- The pinned Go 1.27.2 `net/fd_windows.go`, `internal/poll` and `os/file_windows.go`.

Runtime tests run only in GitHub Actions. On the developer's PC only build/vet
are allowed, using the pinned compiler at Idle priority with two cores.
