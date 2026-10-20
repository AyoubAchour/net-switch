> The owner accepted initiator/sender attribution on 20 October 2026. PR #36 retains the scanner as fallback; the eBPF implementation is a separate follow-up. This study records the research behind that decision, not measured eBPF results.

# Net Switch 1.0: Linux flow ownership with eBPF

20 October 2026 · Read-only design study · Proposed changes, not an amendment to the locked spec

## Recommendation

**Use eBPF as the primary attribution path, with the current sock_diag and `/proc` implementation as a bounded fallback. Do not implement “the socket creator owns all its traffic.”** Record the process that initiates a TCP connection and the process sending UDP, then publish a packet-tuple-to-socket association before delivery to the TUN.

There is a structural problem with discovering ownership after the event: the descriptor or process can disappear before the scan reaches it. Caches and scheduling improvements cannot reconstruct that lost history. However, the evidence does **not** establish that every present miss is caused by that race. A sampled diagnostic job also misses deadlines while reading process metadata after finding a holder.

**This is not a drop-in replacement for §5.6.** The locked design identifies live descriptor holders and treats conflicting app identities as ambiguous. A connect/send recorder identifies an actor at an earlier event. That difference needs an explicit spec decision. If holder semantics must remain exactly as written, use BPF evidence to narrow and prioritise scans; do not call a creator or sender record equivalent proof.

I would not base the 1.0 schedule on more scanner tuning reliably meeting 99.5% in all these storms. Passing a particular run remains plausible; a dependable margin across machines and churn is unproven. Event capture is the better architecture for that margin, but **its complete owner identity, accuracy and cost must pass the real harness before it can replace the primary path**.

| Choice | Assessment |
|---|---|
| Keep tuning the scanner | Can reduce observed deadlines; cannot recover vanished descriptors or provide a fixed worst-case cost independent of descriptor count. |
| Record socket creators only | Reject. Breaks inheritance, exec and descriptor hand-off semantics. |
| Record connect/send activity, with fallback | Recommended, conditional on an approved ownership definition and the validation below. |
| Preserve exact holder semantics using a complete BPF descriptor graph | Possible research direction, but substantially larger than socket attribution. Not recommended for this change. |

## 1. What the existing evidence establishes

### Scope and evidence

I read the local locked `SYSTEM-DESIGN.md`, especially §§5.3–5.6, 5.9 and 10; fetched the two named branches; read their Linux owner code and the namespace harness; and sampled one completed diagnostic job. No code, spec or global instructions were changed. No build, local test, CI run or PR was started.

The source snapshots used were:

- `engine/linux-platform`: `c9d24299a21dc0f18b9fa3d61e62d9ef96dd2449`.
- `engine/linux-platform-round2-ci`: `286ac49f0b183227a14ef6334cb68afb79c6c1f1`.
- Sampled completed diagnostic run: `39424386501`, commit `b86c258e8a8f839222ca23cc1bb9057e2bddb81d`, job `118633114172`.

The stress counts below are supplied by the task, not independently reproduced here. The newest diagnostic run was still running when listed; this report makes no claim about its eventual result.

| Reported workload | Misses | Rate from the supplied numbers | Maximum misses at 99.5% |
|---|---:|---:|---:|
| 65,536-flow cap | 409–574 | 0.624–0.876%, **if 65,536 is the lookup denominator** | 327 on that denominator |
| 9,004-connection window | 77–115 | 0.855–1.277% | 45 |
| 11,532-handshake window | 451 | 3.911% | 57 |

The cap is not necessarily the denominator. The harness attempts nine groups of 7,600 TCP connections, plus other traffic, and counts lookups in the overload window. Its raw `LookupCount` must determine the percentage. Likewise, a lookup count need not equal unique connections or simultaneously live handshakes. The latter two calculations above assume the supplied totals are the intended denominators. [Capacity workload source](https://github.com/AyoubAchour/net-switch/blob/286ac49f0b183227a14ef6334cb68afb79c6c1f1/tests/linux/suite/overload.go)

### There are two different problems

**Discovery scales with unrelated activity.** The implementation already shares descriptor batches, publishes inode hints, remembers useful processes and descriptor ranges, and validates reused hints. Its internal timeout is 8 ms, leaving room inside the 10 ms gate. Fresh negative results still require fresh observations; an earlier scan cannot prove a newly opened descriptor is absent. Those are real constraints, not just inefficient loops. [Owner lookup and deadline, lines 212 onward](https://github.com/AyoubAchour/net-switch/blob/286ac49f0b183227a14ef6334cb68afb79c6c1f1/internal/engine/linux/owners_linux.go#L212), [shared descriptor work](https://github.com/AyoubAchour/net-switch/blob/286ac49f0b183227a14ef6334cb68afb79c6c1f1/internal/engine/linux/owner_batch_linux.go)

**A PID is not yet a usable app identity.** In the sampled job, a 300-lookup phase had six timeouts, with zero missing, ambiguous or other errors. One diagnostic had a socket query taking 13.154 microseconds but holder validation taking 10.876 ms. Across that phase, four timeouts named descriptor-batch waiting as their largest measured phase and two named opening identity metadata; a metadata open reached 10.475 ms. Elapsed phases include scheduling delays, so this does not prove disk I/O took that time. It proves that replacing inode discovery alone would not automatically fix every deadline. [Completed diagnostic job](https://github.com/AyoubAchour/net-switch/actions/runs/39424386501/job/118633114172)

That diagnostic is a different revision and workload from the supplied storm results. It does not invalidate the reported steady-state passes; it limits what can honestly be inferred about the causes of the remaining misses.

### Why there is a structural limit

Consider a UDP sender that sends one datagram, closes the socket and exits. The kernel can queue the packet before the engine runs. Later, neither the descriptor nor the executable link exists. Making the scan faster improves the probability of winning this race; it cannot guarantee winning it. OpenSnitch documents this exact class of problem with `/proc` attribution. [OpenSnitch's explanation](https://github.com/evilsocket/opensnitch/wiki/Why-OpenSnitch-does-not-intercept-application-XXX/c1e654bee0462544989c421ffcbaa8ff038467d1)

Long-lived TCP sockets are different: their ownership remains discoverable. Deadline misses there can be scheduling, contention, repeated validation or insufficient scan throughput. The supplied counts alone do not prove an unavoidable 0.5% floor. The honest conclusion is **structural vulnerability plus demonstrated budget pressure**, not a mathematical impossibility theorem for this particular benchmark.

To keep the current architecture and credibly meet the gates would require phase-level distributions on the same stress runs, sufficient scan capacity and scheduler headroom on both architectures, safe identity caching across exec, and repeated passes with a margin. Increasing the deadline, accepting stale holders, skipping conflicts or excluding genuine misses would change the contract rather than solve it.

## 2. How comparable tools do it

### OpenSnitch

OpenSnitch is the closest precedent. Its inspected BPF source records TCP information with entry/return probes on `tcp_v4_connect` and `tcp_v6_connect`, and UDP information at `udp_sendmsg` and `udpv6_sendmsg`. It stores tuple-to-PID/UID information in kernel maps. Its connection resolver tries BPF, then falls back to netlink/socket information and inode-to-process discovery. [BPF source](https://github.com/evilsocket/opensnitch/blob/master/ebpf_prog/opensnitch.c), [fallback source](https://github.com/evilsocket/opensnitch/blob/master/daemon/conman/connection.go)

The return-probe TCP approach can publish after the SYN has already left the function's internal transmit path. A queued firewall packet gives userspace time, but does not make publication precede transmission. Bounded maps and temporary entry/return state can also fill. These are reasons to adopt the event-capture principle, not that exact implementation.

Its documentation says eBPF became the default in 1.4.0 and requires the relevant BPF/kprobe kernel support. Source retains compatibility work for old 4.4 kernels; that is not a promise that every current package works on every 4.4 configuration. On our 5.8 floor the main question is enabled features, probe availability and policy. [Monitoring documentation](https://github.com/evilsocket/opensnitch/wiki/monitor-method-ebpf), [requirements](https://github.com/evilsocket/opensnitch/wiki/Dependencies-and-how-it-works)

### Portmaster and other desktop firewalls

Portmaster's inspected Linux listener uses `fentry/tcp_connect` and return hooks for IPv4/IPv6 UDP connect, sends events through a ring buffer, and loads precompiled objects with `cilium/ebpf`. Its loader adapts to UDP function renaming around Linux 6.13. This is concrete evidence both for the Go packaging model and for the maintenance cost of internal kernel hooks. [Probe source](https://github.com/safing/portmaster/blob/development/service/firewall/interception/ebpf/programs/monitor.c), [loader source](https://github.com/safing/portmaster/blob/development/service/firewall/interception/ebpf/connection_listener/worker.go)

Those three listener hooks do not by themselves cover unconnected UDP sends. An asynchronously consumed event can also arrive after the packet unless a separate synchronisation scheme handles it. The inspected listener is not evidence of a 99.5% first-packet guarantee. Fentry began on x86 in the 5.x series; it cannot be assumed available on arm64 5.8.

Douane illustrates the kernel-module alternative: its separate DKMS component moves firewall machinery into a module. That entails a kernel build/ABI and Secure Boot signing burden, rather than avoiding kernel integration. I found no useful comparable storm benchmark or verified current kernel-support matrix, and would not use it to justify our thresholds. [Douane](https://github.com/Douane/Douane), [DKMS component](https://github.com/Douane/douane-dkms)

### Cilium and Tetragon

Cilium uses cgroup connect/sendmsg hooks for socket-level networking, plus packet-level mechanisms and maps. Its policy identity is principally endpoint/workload identity; that is different from resolving a desktop executable and all its socket holders. Current stable documentation requires Linux 5.10 or a specified RHEL backport baseline; copying that product's support claim would not establish ours on 5.8. [Socket programs](https://github.com/cilium/cilium/blob/main/bpf/bpf_sock.c), [requirements](https://docs.cilium.io/en/stable/operations/system_requirements/)

Tetragon makes the distinction particularly clear. Its socket tracking can capture the creating process at `sk_alloc`, then use that record when later network hooks run outside the originating task. Its documentation explicitly lists LRU eviction and socket sharing as limitations: creator attribution can outlive the creator and differ from the process using a passed socket. Socket tracking requires at least 5.3; its current fentry implementation has a separate 6.1 requirement. [Tetragon hook and socket-tracking documentation](https://tetragon.io/docs/concepts/tracing-policy/hooks/)

The lesson is to retain identity before asynchronous network work, while treating overflow, sharing and stale identity as correctness problems. Tetragon's example explicitly pairs creation tracking with `__sk_free` cleanup; its process structures also separate TGID, namespace PID and execution-time identity. [Socket-tracking example](https://github.com/cilium/tetragon/blob/main/examples/tracingpolicy/datagram-with-sock-tracking.yaml), [process-state source](https://github.com/cilium/tetragon/blob/main/bpf/lib/process.h)

### Falco

Falco's modern probe captures kernel/syscall events and reconstructs process and descriptor state in userspace. It is a broader observability system, not an inline tuple-to-app API for the first TUN packet. Its modern probe is shipped prebuilt and normally needs the feature set available in 5.8: BTF and BPF ring buffers. Backports can alter the effective floor. [Probe architecture and requirements](https://falco.org/docs/concepts/event-sources/kernel/), [kernel event architecture](https://falco.org/docs/concepts/event-sources/kernel/architecture/)

Its inspected connect probe operates at syscall exit and records the result, FD and tuple for success or EINPROGRESS. That is useful event evidence, but is later than first-SYN transmission. An event stream can lose records under load; rebuilding a descriptor graph from it requires explicit loss handling. This is why our critical ownership record should be synchronously readable from a map, with events used for notification and enrichment. Falco's broad instrumentation costs are not a defensible estimate for our narrower program. [Falco connect probe](https://github.com/falcosecurity/libs/blob/master/driver/modern_bpf/programs/tail_called/events/syscall_dispatched_events/connect.bpf.c)

### bpftrace/BCC `tcplife`

The inspected bpftrace script caches task information during selected TCP states and prints at close. Its own comments call PID/command attribution best effort, with possible wrong results. That script uses `kprobe:tcp_set_state`; packaged manuals and BCC implementations also describe the `sock:inet_sock_set_state` tracepoint introduced in 4.16. These variants should not be conflated. [bpftrace script](https://github.com/bpftrace/bpftrace/blob/master/tools/tcplife.bt), [BCC implementation](https://github.com/iovisor/bcc/blob/master/tools/tcplife.py)

It is useful for lifetime measurement, not first-SYN admission. In particular, Linux 5.8 enters SYN_SENT before allocating the ephemeral source port. Merely observing that state does not supply the final tuple. [Linux TCP connect ordering](https://github.com/torvalds/linux/blob/v5.8/net/ipv4/tcp_ipv4.c#L251)

### nftables and systemd

`meta skuid` supplies the originating socket's UID, not a process or executable. `meta cgroup` is the cgroup-v1 `net_cls` class ID, not a cgroup-v2 process identity. The separate `socket cgroupv2` expression matches a socket's cgroup ancestry. That expression is present in Linux 5.13 and absent in 5.12, so it cannot be required at our 5.8 floor. [nftables manual](https://netfilter.org/projects/nftables/manpage.html), [5.13 socket expression source](https://github.com/torvalds/linux/blob/v5.13/net/netfilter/nft_socket.c)

Systemd's per-unit IP filtering uses cgroup BPF. `IPAddressAllow`/`IPAddressDeny` date to systemd 235; cgroup packet hooks exist before 5.8. This is efficient because the unit is already the policy boundary. Socket-activated services have separate socket-unit and service-unit treatment. It does not solve arbitrary desktop process ownership, and moving or passing a socket does not turn its original cgroup into its current holder. [systemd manual](https://www.freedesktop.org/software/systemd/man/latest/systemd.resource-control.html), [firewall implementation](https://github.com/systemd/systemd/blob/main/src/core/bpf-firewall.c)

None of these projects supplies a published result establishing our exact accuracy, latency, identity and storm requirements.

## 3. Decide what “owner” means first

| Definition | Example | Consequence |
|---|---|---|
| Socket creator | A creates a socket; B inherits it and connects. | Reports A. Fails existing inheritance and hand-off requirements. |
| Connection initiator | A creates it; B connects. | Reports B at connection initiation, even if A retains a descriptor. |
| UDP sending app | A creates/connects it; B sends the first datagram. | Reports B only if a send hook actually observes B. |
| Live holders, as in §5.6 | A and B both hold it, with different identities. | Ambiguous even if only B sends. Requires holder evidence, not just a sender record. |

The existing tests deliberately distinguish these cases. `lookup.ambiguous-holders` expects the main line when bravo and charlie both retain the socket. The inherited and cross-user hand-off cases expect the receiver that subsequently connects. A connect hook would pass the latter two while changing the first. [Existing ownership cases](https://github.com/AyoubAchour/net-switch/blob/286ac49f0b183227a14ef6334cb68afb79c6c1f1/tests/linux/suite/lookup.go)

**Recommended proposed contract:** a new TCP flow belongs to its initiating process incarnation and executable generation; a new UDP session belongs to the first observed sending app for that socket generation. Preserve that decision for the session, with an explicit conflicting-sender state if another app uses the same socket. This is a connection/session attribution rule, not a claim to identify the actor behind every later packet.

Under that proposal, an idle second holder alone no longer makes a flow ambiguous. If retaining that protection is a requirement, do not adopt this shortcut: BPF can give candidate PIDs, but the holder checks remain. A hybrid does not reconcile two different definitions merely by naming one a fallback; stats and results must state whether they are observed initiation/send records or present-holder fallback results.

A complete event-driven holder graph would need fork/clone and shared file tables, dup/close/close_range, exec and close-on-exec, exit, descriptor receipt, pidfd descriptor duplication, and io_uring-held references, plus startup reconstruction. Missing one transition corrupts the graph. That is far larger than recording socket operations.

## 4. A concrete design for the TUN engine

This is a proposed architecture inferred from the source ordering, not code that has been built or verified.

### 4.1 Separate the three joins

Keep these records distinct:

1. **Process identity:** host TGID, process start token, executable generation, executable evidence, app identity and metadata status.
2. **Socket activity:** network namespace, socket cookie, process-identity reference, event kind, timestamps and conflict/status flags.
3. **Packet association:** network namespace plus the actual packet's family, protocol, source/destination addresses and ports → socket cookie and identity-generation reference.

TGID is the Linux process ID visible as PID in the host; a thread ID alone is insufficient. A start token protects against PID reuse. An executable generation is also necessary: successful exec normally keeps the PID and process start time.

Publish the kernel records synchronously before the relevant packet proceeds. The engine looks up the tuple map directly, then the identity record. A ring-buffer reader must not be the sole way the primary lookup learns ownership.

### 4.2 Hooks and their exact roles

| Hook | Use | Boundary or limitation |
|---|---|---|
| `cgroup/sock_create` | Record creation evidence and initialise a cookie record. | No complete tuple; creator is only provenance. Existing sockets predate it. |
| `cgroup/connect4/6` | Record the calling process and socket cookie before TCP/UDP connect proceeds. | TCP ephemeral source port can still be zero. A failed connect is intent, not a transmitted flow. |
| `cgroup/sendmsg4/6` | Record the caller for the unconnected UDP send path. | Not a hook for every send on a connected UDP socket. Final selected source IP may still need packet-stage resolution. |
| `cgroup/post_bind4/6` | Record explicit local binding if useful. | Explicit bind is not every automatic bind, and it supplies no general remote endpoint. Not the tuple publisher. |
| `sock_ops`, `BPF_SOCK_OPS_TCP_CONNECT_CB` | Associate a TCP cookie with the selected tuple before its SYN. | TCP only. Do not wait for ACTIVE_ESTABLISHED. |
| `cgroup_skb/egress` | Read the real outgoing packet tuple and socket cookie, then publish their association before TUN delivery. | Never infer PID from the task currently running this hook. Some packets lack a usable full socket. |
| UDP entry probes | Cover sends on already-connected UDP sockets and detect different sending apps. | Internal hooks require compatibility checks; async workers and shared/corked sends require careful attribution. |
| Process fork/exec/exit tracepoints | Maintain executable generations and identity history. | Event delivery and metadata completeness must be bounded and observable. |

The decisive TCP ordering is visible in 5.8: `tcp_v4_connect` selects the port before calling `tcp_connect`; the latter invokes TCP_CONNECT_CB before transmitting the SYN. IPv6 also allocates its port before calling `tcp_connect`. This avoids the publication race of a return probe on the outer connect function. Both families and Fast Open must still receive explicit runtime tests. [IPv4 connect](https://github.com/torvalds/linux/blob/v5.8/net/ipv4/tcp_ipv4.c), [IPv6 connect](https://github.com/torvalds/linux/blob/v5.8/net/ipv6/tcp_ipv6.c), [SYN construction and callback](https://github.com/torvalds/linux/blob/v5.8/net/ipv4/tcp_output.c)

For ordinary UDP sendmsg, automatic port binding precedes the UDP protocol send routine. The 5.8 IPv4 and IPv6 UDP code invoke the cgroup sendmsg hook on the non-connected path. A connected UDP socket can therefore send without that hook. [Automatic bind/send dispatch](https://github.com/torvalds/linux/blob/v5.8/net/ipv4/af_inet.c), [IPv4 UDP](https://github.com/torvalds/linux/blob/v5.8/net/ipv4/udp.c), [IPv6 UDP](https://github.com/torvalds/linux/blob/v5.8/net/ipv6/udp.c)

For complete UDP sender coverage, use a tested entry probe at `udp_sendmsg`/`udpv6_sendmsg` or an equivalently complete socket-send hook. Prefer fentry when the actual kernel supports it; retain an architecture-aware kprobe variant at 5.8. Do not assume the networking `bpf_get_socket_cookie` helper accepts an arbitrary `struct sock *` in a 5.8 tracing program. The probe can read an already-initialised cookie from the socket; if that evidence is unavailable, report missing capture and use fallback. Creation/connect/sendmsg cgroup hooks initialise cookies through their supported helpers.

This last point matters at startup: connected UDP sockets created before attachment may have no activity record. They need explicit bootstrap/fallback handling, not an invented creator.

### 4.3 Publish the tuple at the packet boundary

Use the egress hook as the canonical tuple bridge, especially for UDP wildcard binds, route-selected source addresses, IPv4-mapped IPv6 and address rewriting by other software. TCP sock_ops can publish early, but cannot alone account for a later rewritten tuple.

The 5.8 IPv4 output path runs cgroup egress before finishing output and fragmentation. The proposed program observes and returns “allow”; it changes no route, mark, address or verdict. It handles SYNs and relevant UDP packets, doing minimal work on other traffic. IPv6 extension headers, fragmentation and GSO need bounded parsing and explicit tests. [IPv4 output ordering](https://github.com/torvalds/linux/blob/v5.8/net/ipv4/ip_output.c)

At egress, join through the socket cookie to the previously captured actor. Carry the socket's network-namespace identity in that record; do not assume every program type supports every namespace helper on 5.8. Do not read `current` and label a softirq worker as the application.

Read only tuples delivered toward this engine's TUN. Exclude the engine's own line-bound sockets, other namespaces and ordinary bypass traffic as early as the available context permits. Initial socket tracking can still see sockets that never reach the TUN, so its capacity must be budgeted separately from admitted flows.

### 4.4 Maps, cookies and socket-local storage

**A cookie-keyed hash map and `sk_storage` are different interfaces.** Socket-local storage is attached to the socket, is freed with it, and is accessed in BPF through a socket pointer. Ordinary userspace map access uses a socket FD, not its cookie. The engine does not own every application's FD. Therefore it still needs an exported cookie/tuple map or a specifically implemented diagnostic-storage query. [Socket-storage documentation](https://www.kernel.org/doc/html/v7.0/bpf/map_sk_storage.html), [5.8 FD-based implementation](https://github.com/torvalds/linux/blob/v5.8/net/core/bpf_sk_storage.c)

At 5.8, storage helpers are available to useful sock_addr, sock_ops and cgroup_skb paths, but not automatically to every hook, including sock_create. A bounded cookie hash is the simpler common interface. Optional socket-local state can reduce repeated work where supported. [5.8 helper dispatch](https://github.com/torvalds/linux/blob/v5.8/net/core/filter.c)

An exact sock_diag lookup can supply the same cookie: diagnostic code and the BPF networking helpers use the socket's generated cookie. That removes inode-to-PID scanning when the cookie map contains valid identity, but still requires a live discoverable socket and a netlink round trip. Use this as a secondary path, not the only bridge. UDP reuse-port lookup is not proof of which socket sent an outbound datagram. [Diagnostic cookie implementation](https://github.com/torvalds/linux/blob/v5.8/net/core/sock_diag.c)

For authoritative records, prefer bounded ordinary hash maps with explicit insertion-failure counters over silent LRU eviction. LRU remains useful for disposable hints. Its replacement policy can evict a valid owner precisely during the storm we are trying to fix. Map updates must publish coherent records, with generation checks rather than separately updated fields that readers could combine. [Kernel hash/LRU documentation](https://docs.kernel.org/bpf/map_hash.html)

Retain bounded historical records long enough to cover queued first packets and the lookup deadline. Do not immediately erase the only owner evidence on close. Reclaim acknowledged or expired records safely, keep live session references valid, and preserve the existing UDP destroy notification and one-second reconciliation protections. On 5.8, there is no cgroup sock_release hook to make that cleanup automatic.

### 4.5 Obtain a complete app identity

Move repeated identity discovery out of individual flow lookups:

- Before enabling capture routes, attach lifecycle observation and seed identities for existing processes with race checks. Reconcile the seed against concurrent fork/exec/exit activity.
- At socket activity, capture a process incarnation and executable generation in kernel state. On 5.8, privileged current-task access plus CO-RE field reads can obtain the group leader's start information and executable evidence.
- Cache normalised executable paths and Flatpak/Snap/AppImage identity per process/executable generation. Keep the present trust checks on process-root metadata. A cgroup name remains evidence to verify, not permission to invent an app ID.
- At successful exec, publish the new generation before it can be confused with the old image. A `(pid, start time)` cache alone is unsafe across exec.
- Retain resolved identity after process exit while referenced by a pending/active flow. Failure to read `/proc/<pid>/exe` later must not erase previously established evidence.

**There is no universal “give me the full trusted app identity” BPF helper.** `comm` is not a path. The exec tracepoint's filename is not necessarily the canonical executed image, particularly for scripts and symlinks. The convenient `bpf_d_path` helper is later than the floor (5.10) and has attachment restrictions. [5.10 path-helper allowlist](https://github.com/torvalds/linux/blob/v5.10/kernel/trace/bpf_trace.c)

For short-lived processes on 5.8, capturing executable file/mount evidence and a bounded path snapshot at exec may require our own CO-RE path traversal, with explicit truncation and unresolved flags. Flatpak metadata and registered AppImage identity still need a trusted userspace association. A process that exits before that association is established can remain unknown. Counting a PID-only hit as successful attribution would make the gate dishonest.

Keep kernel nanosecond start tokens and `/proc` clock-tick start values explicitly typed; convert using the correct boot-time basis and clock-tick rate. Include a boot/session epoch so persisted or pinned records cannot be mistaken for current ones.

### 4.6 Races that need defined outcomes

**First packet before publication.** Synchronous map writes at the pre-transmit/egress hooks solve this for covered paths. Writing only to a ring buffer does not: userspace consumption can lag. Metadata enrichment can still lag, so the 10 ms deadline must cover that wait too.

**Port reuse.** Store cookie and process/executable generation, never just a tuple-to-PID TTL. A late destroy event must match the old cookie. Preserve bounded recent generations rather than blindly overwriting a tuple with the newest socket.

**Information missing from the TUN packet.** A packet contains no socket cookie. Two sockets can produce indistinguishable UDP packets with the same tuple, and an old queued datagram can survive a close/rebind. A current sock_diag answer or “latest tuple entry” cannot identify that old packet. Mark an unresolved collision unknown. For TCP SYNs, the initial sequence number can help distinguish retained generations; timestamps alone are not proof. Completely eliminating this ambiguity would need a packet-associated metadata channel or earlier policy enforcement, a larger design change.

**Fork, exec and descriptor passing.** Creator evidence is replaced/supplemented by the actual connecting or sending actor. Existing TCP flows retain their original decision. Connected UDP requires send coverage after transfer. If different apps concurrently send on one socket, a mutable “last sender” slot races; retain conflict state rather than assigning queued packets to whichever process ran last.

For the proposed UDP rule, invalidate the existing session when a different sending app is observed and resolve subsequent traffic as ambiguous/unknown for that socket generation. This deliberately errs toward unknown even if the first app has since stopped using the socket. Check the generation/conflict status before subsequent UDP forwarding, not just at session creation; otherwise the new evidence cannot affect the old session. That adds hot-path cost and a small platform-interface change, both of which need measurement. Exact sender attribution for an already queued indistinguishable datagram remains subject to the collision limitation above.

**Async I/O and corking.** io_uring worker context need not be the submitting process. UDP corking can combine work, and sendpage/other paths must be checked against the chosen hooks. An unexpected worker or uncovered path is missing evidence, not an app identity. Supporting these cases may require submission-to-execution correlation; it cannot be promised from a generic PID helper.

**IPv4/IPv6 and QUIC.** Normalise packet family independently of socket family; test IPv4-mapped IPv6, wildcard binds and explicit source selection. QUIC is UDP for ownership. Multiple destinations on one UDP socket must continue sharing the single endpoint-independent session required by §5.3; do not grow unbounded ownership state for every QUIC destination.

**Containers and namespaces.** Include a socket network-namespace identifier in keys and host PID incarnation in process identity. Use the socket's namespace, not the caller's current namespace: descriptors can cross boundaries. The locked routing design leaves forwarded container/VM traffic alone. Do not broaden that scope. Host-network containers and sandboxed desktop apps do need attribution; identical `/app/bin/...` paths must stay distinct through app metadata.

## 5. Requirements and compatibility

### Kernel 5.8 feature audit

Kernel version alone does not establish configuration, architecture, helper availability or permission. Probe the exact program/map/helper combinations at startup.

| Feature | Upstream availability relevant here | At 5.8 |
|---|---|---|
| cgroup sock_create and packet egress | 4.10 | Available with cgroup BPF configuration. |
| sock_ops | 4.13; TCP_CONNECT_CB is present in 5.8 | Suitable for the TCP pre-SYN bridge. |
| connect4/6, bind4/6, post_bind4/6 | 4.17 | Available; source-port timing remains hook-specific. |
| UDP sendmsg4/6 | 4.18 | Available for the non-connected send path, not all UDP sends. |
| Socket-local storage | 5.2 | Available, with program-type/helper restrictions. |
| Network-namespace cookie helper | Present for sock and sock_addr in the inspected 5.8 source | Use those contexts; do not assume skb/tracing support. |
| BPF ring buffer | 5.8 | Available; optional notification transport, not the authoritative join. |
| Cgroup `bpf_link` attachment | 5.7 | Available; prefer actual link ownership over implicit legacy fallback. |
| BTF/CO-RE | Requires usable target type information and supported relocations | Optional kernel configuration, not guaranteed by 5.8. |
| fentry/fexit | 5.5-era x86 support; arm64 trampoline support arrived later, in 6.0 | Cannot be the sole 5.8 x64/arm64 implementation. |
| cgroup sock_release | 5.9 | Unavailable at the floor. |
| `bpf_d_path` | 5.10, restricted attachment contexts | Unavailable at the floor. |
| Task storage / current-task-BTF convenience | 5.11-era additions | Do not require them for the floor implementation. |
| `socket cgroupv2` nft expression | 5.13 | Unavailable at the floor. |

Sources: [bpftool hook reference](https://github.com/libbpf/bpftool/blob/main/docs/bpftool-cgroup.rst), [5.8 UAPI](https://github.com/torvalds/linux/blob/v5.8/include/uapi/linux/bpf.h), [5.8 helper dispatch](https://github.com/torvalds/linux/blob/v5.8/net/core/filter.c), [5.8 base helpers](https://github.com/torvalds/linux/blob/v5.8/kernel/bpf/helpers.c), [5.7 link creation](https://github.com/torvalds/linux/blob/v5.7/kernel/bpf/syscall.c), [arm64 6.0 BPF JIT](https://github.com/torvalds/linux/blob/v6.0/arch/arm64/net/bpf_jit_comp.c), [portable BPF guidance](https://ebpf-go.dev/guides/portable-ebpf/).

One documentation discrepancy was checked against source: bpftool's reference says sock_ops dates to 4.12, but `BPF_PROG_TYPE_SOCK_OPS` is absent in the [4.12 UAPI](https://github.com/torvalds/linux/blob/v4.12/include/uapi/linux/bpf.h) and present in [4.13](https://github.com/torvalds/linux/blob/v4.13/include/uapi/linux/bpf.h). Either way it is available at our floor.

Use `CONFIG_BPF`, `CONFIG_BPF_SYSCALL`, `CONFIG_CGROUP_BPF`, the appropriate network families and a usable JIT; CO-RE task reads require BTF; tracing variants need the relevant tracing/kprobe/ftrace configuration. Avoid newer atomics, kfuncs and convenience helpers unless isolated behind verified optional variants.

### Distribution differences

| Target | What can be concluded from this study | What must be tested on the actual image |
|---|---|---|
| Ubuntu 24.04 | Its GA kernel family is 6.8, above the floor; HWE/flavour kernels differ. | BTF, service capabilities, AppArmor and Secure Boot behaviour. |
| Ubuntu 26.04 | Official release notes specify kernel 7.0. | The same checks; also changed internal probe signatures. |
| Debian 13 | The release uses the 6.12 kernel family. | Exact signed kernel/flavour, BTF and active security policy. |
| Fedora 44/45 | Kernel versions change within a release; a Fedora label is not a fixed kernel ABI. | Shipped kernel/BTF, enforcing SELinux and Secure Boot. Do not infer Fedora 45 readiness from Fedora 44. |
| Arch | Rolling kernel packages are well above 5.8; custom/hardened variants require their own checks. | Actual configuration, BTF and lockdown policy after each supported update. |

References: [Ubuntu kernel lifecycle](https://ubuntu.com/kernel/lifecycle), [Ubuntu 26.04 kernel release notes](https://documentation.ubuntu.com/release-notes/26.04/changes-since-previous-interim/), [Debian 13 release announcement](https://bits.debian.org/2025/08/trixie-released.html), [Fedora kernel update policy](https://fedoraproject.org/wiki/Kernel), [Arch kernel package](https://archlinux.org/packages/core/x86_64/linux/).

This study did not boot these images or verify their installed BTF/configuration files. Fedora's schedule endpoint was inaccessible through the fetched sources, so no final Fedora 45 release/kernel claim is made. Treat each named target as a validation requirement, not a checkmark.

BTF normally comes from `/sys/kernel/btf/vmlinux`. If absent, a verified matching external BTF file is technically possible, but maintaining a database of exact kernel types is a separate distribution burden. Prefer fallback to silently choosing approximate offsets.

### Privileges, lockdown and service confinement

Root is insufficient if the service's bounding set removes needed capabilities. On 5.8, plan for **CAP_BPF and CAP_NET_ADMIN**, plus **CAP_PERFMON** for tracing and privileged task/kernel reads. The older CAP_SYS_ADMIN alternative is much broader and should not be added merely to avoid configuring the specific capabilities. Existing `/proc` identity access can require separate permissions, including cross-user ptrace-style checks. [5.8 load permission checks](https://github.com/torvalds/linux/blob/v5.8/kernel/bpf/syscall.c), [helper privilege checks](https://github.com/torvalds/linux/blob/v5.8/kernel/bpf/helpers.c)

On kernels before 5.11, BPF allocations generally consume the memlock allowance. Set an adequate explicit service limit or raise it before loading; changing a hard limit can require CAP_SYS_RESOURCE. Newer kernels generally use memory-cgroup accounting. Neither mechanism makes Go's `GOMEMLIMIT` account for kernel maps. [cilium/ebpf resource-limit documentation](https://ebpf-go.dev/concepts/rlimit/)

`kernel.unprivileged_bpf_disabled` restricts unprivileged callers; it is not a blanket prohibition on a correctly privileged service. Do not disable that system protection. Seccomp and systemd restrictions can still block `bpf`, `perf_event_open`, cgroup access or required files.

**Secure Boot does not have one universal BPF outcome.** Ubuntu documents integrity lockdown tied to Secure Boot. Upstream 5.8 distinguishes integrity from confidentiality restrictions, and kernel-memory probe reads consult lockdown policy. Consequently, networking hooks may work while identity/tracing features fail, and downstream policy can be stricter. Test the actual program with Secure Boot enabled; report a specific failure and select fallback. Do not ask users to disable Secure Boot as the normal installation path. [Ubuntu lockdown documentation](https://documentation.ubuntu.com/security/security-features/kernel-protections/), [5.8 lockdown classes](https://github.com/torvalds/linux/blob/v5.8/include/linux/security.h), [probe-read checks](https://github.com/torvalds/linux/blob/v5.8/kernel/trace/bpf_trace.c)

For SELinux/AppArmor, test the packaged service domain/profile, not just an unconfined root shell. Preserve enforcement and ship narrowly justified policy where necessary. Missing rights must identify the failed operation in diagnostics; a generic “BPF unavailable” message makes distribution failures hard to fix.

### Go tooling, original bytecode and reproducibility

**Yes: our own BPF source can be compiled in CI by a committed generator, embedded in Go, and shipped without clang on users' machines.** CO-RE means the loader adjusts recorded type accesses to the target kernel; it does not mean compiling source on the desktop.

`github.com/cilium/ebpf` is MIT-licensed and is a Go loader/library, not the Cilium networking product. The Go module proxy reported **v0.22.0**, released 26 June 2026, at study time; that tag declares Go 1.25.0, compatible with the inspected Net Switch branch's Go 1.27.2. Pin the library and `bpf2go` together, vendor the selected runtime dependencies, and record checksums. Do not use moving `main` for a release. [Versioned module](https://github.com/cilium/ebpf/blob/v0.22.0/go.mod), [license](https://github.com/cilium/ebpf/blob/v0.22.0/LICENSE), [library requirements](https://github.com/cilium/ebpf/blob/v0.22.0/README.md)

Recommended reproducible build:

1. Commit original BPF C, map schemas, the generator and exact header/toolchain inputs.
2. Pin a Linux build container by digest, including clang/LLVM, header versions and the BTF/type-generation inputs.
3. Generate `.o` and Go bindings with deterministic source paths; preserve BTF/CO-RE sections. Commit generated outputs and regenerate/diff-check them in CI.
4. Embed the objects. Test the exact embedded artifacts, including architecture-specific probe variants, on x64 and arm64. Shared little-endian BPF does not remove architecture-specific register access in kprobes.
5. Keep runtime builds independent of clang, libbcc and a system libbpf shared library. A builder needs LLVM; the installed engine does not.

This matches the library's documented portable build model. CO-RE handles structure layout, not removed functions, unavailable helpers, all verifier differences or changed semantics. The library does not promise support for end-of-life kernel 5.8; our advertised floor therefore requires our own compatibility tests. [Build guide](https://ebpf-go.dev/guides/getting-started/), [portability guide](https://ebpf-go.dev/guides/portable-ebpf/)

**Licensing is an explicit design input.** No implementation from OpenSnitch, Cilium, Tetragon, Falco or the kernel should be copied. Some useful helpers, including current-task access in 5.8, require a GPL-compatible BPF program declaration. We can write and license our own small BPF program, for example with an explicit dual MIT/GPL grant, while retaining MIT for the Go engine. That is different from copying GPL implementation code. Record the real licensing choice and any deliberate use of permissive helper headers in §8 and notices; a string in an ELF is not a substitute for licensing the source accordingly. [Kernel BPF licensing rules](https://docs.kernel.org/bpf/bpf_licensing.html)

The final binary-size increase is **not measured**. It consists of the linked Go loader/BTF code and our objects, not an installed compiler. The module's complete development dependency list is not the executable's linked dependency set. Measure stripped release binaries and vendored runtime source separately; do not promise a particular size from the module archive.

### Attachment lifecycle and fallback

Attach observation before installing capture routes. In production, cover the host cgroup-v2 hierarchy needed for all applications, not just the engine's service cgroup. In the harness, use its isolated subtree. Coexist with existing programs; never replace another application's attachment or rely on overriding it.

Prefer kernel link objects tied to the engine lifetime, held explicitly in Go. Avoid pinning by default. The library's high-level attach method can fall back to legacy attachment, whose crash lifetime differs; either require the proper link mechanism for this mode or journal and clean up that exact attachment. Never assume closing a Go object after a crash detached a legacy program. [Cgroup loader implementation](https://github.com/cilium/ebpf/blob/v0.22.0/link/cgroup.go), [object/pinning lifecycle](https://ebpf-go.dev/concepts/object-lifecycle/)

If pinning is deliberately needed, use a root-owned versioned bpffs location, instance/schema identity, validated reuse and cleanup. Pins survive the process, not reboot, and can preserve stale state.

Fallback has two levels:

- **Per lookup:** direct tuple record → diagnostic cookie record → existing live-holder lookup, all under the same total deadline. An uncertain tuple collision must not be “resolved” by selecting an arbitrary diagnostic socket.
- **Per machine:** if required hooks, BTF or permissions are absent, select the existing backend and expose its reason and limitations. Reuse its ambiguity checks, PID/start validation and UDP generation protection.

A fallback is availability insurance, not evidence that the unsupported machine meets the BPF storm guarantee. If full 99.5% stress performance is promised on every supported configuration, the forced-fallback matrix must pass too. Otherwise the spec must explicitly identify fallback as a degraded performance mode; this study does not silently weaken the locked guarantee.

## 6. CPU, memory and maintenance costs

### Bounded cost, not zero cost

The expected algorithmic gain is replacing repeated work over processes/descriptors with a small number of map operations per covered event and per new flow. The cost moves partly into application syscalls and the kernel packet path. UDP send observation and egress hooks can execute for every datagram/packet even if the map needs updating only once. Process lifecycle tracking also runs when there is no captured traffic.

No honest CPU percentage or p95 can be derived without implementing and running this workload. Measure kernel hook cost, engine CPU, application throughput and first-connect/send latency together. A fast userspace lookup can hide expensive hooks upstream.

### Illustrative memory budget

The following is sizing arithmetic, **not an allocation measurement**:

| Component | Illustrative sizing | Payload only |
|---|---|---:|
| Cookie records | 131,072 × (8-byte key + 64-byte value) | 9 MiB |
| Tuple records | 131,072 × (48-byte key + 48-byte value) | 12 MiB |
| Notification ring | Fixed 4 MiB | 4 MiB |
| Process metadata | Shared between flows, total byte cap | Separate, proposed 16 MiB userspace cap |

Kernel hash buckets, element headers, alignment, locks, program/JIT storage and any socket-local state add overhead. An initial **64 MiB kernel-attribution budget** is a reasonable engineering allowance to validate, not a proven upper bound. Reject the design or change sizing if measured allocations exceed it. Avoid per-CPU copies of flow maps; reserve per-CPU storage for small counters/scratch space.

Why 131,072 rather than 65,536? The BPF layer sees pending and rejected attempts, queued historical generations, and sockets outside the admitted-flow count. It also needs room for UDP. Even twice the flow cap is not proof against arbitrary churn. Explicitly bound lifetime, insertion rate, metadata bytes and collision history; pressure must produce counted misses/fallback, never a false owner.

Socket-local storage is automatically reclaimed but is not capped by `max_entries` like an ordinary hash. Using it for every socket in the host without a separate allocation strategy would undermine the budget. Kernel memory must appear in capacity reports alongside Go heap/RSS; the existing 512 MiB Go target does not cover it.

### Rebase and maintenance

Keep the existing owner-result shape and UDP cookie protection where possible. Add the BPF resolver behind the Linux platform layer, retain the tested scanner, and share identity normalisation and diagnostics. The proposed conflicting-sender rule needs an additional UDP identity-status check; that should be an explicit interface extension. Routing and netstack code should not need a rewrite for the join.

The larger changes are lifecycle/capabilities, identity history, the generator/toolchain, map accounting and tests. They also touch the spec's dependency allowlist. Replacing the primary path can retire some scanner tuning from common traffic, but maintaining fallback still means supporting two backends.

Cgroup UAPI hooks are the lower-maintenance foundation. Internal UDP probes and path traversal are the main ongoing kernel-compatibility liabilities. Portmaster's attach-name adaptation is a real example of this cost. Rebase churn should be contained by adding a backend rather than continually rewriting the in-progress scanner.

## 7. Required validation in `tests/linux/`

The current cold lookup gate creates 300 TCP connections per phase, sequentially and ten at a time, with 10,000 unrelated open files. It tests both terminal and app-scope cases. The overload wrapper separately applies the 99.5% rule to each non-injected lookup window. These are valuable but do not establish UDP first-packet, BPF overflow or pre-attachment coverage. [Cold gate](https://github.com/AyoubAchour/net-switch/blob/286ac49f0b183227a14ef6334cb68afb79c6c1f1/tests/linux/suite/lookup.go), [overload accounting](https://github.com/AyoubAchour/net-switch/blob/286ac49f0b183227a14ef6334cb68afb79c6c1f1/tests/linux/suite/suite.go#L96)

Run the existing suite against forced BPF and forced fallback modes, plus mixed operation. The exact additions should be:

1. **First-packet ordering:** delay the userspace event reader while sending TCP SYNs and first UDP datagrams. Critical map attribution must still work; a delayed metadata dependency must be reflected in latency/misses.
2. **TCP variants:** IPv4, IPv6, mapped IPv6, nonblocking connect, failed connect/retry, retransmitted SYN, Fast Open and source-bound sockets.
3. **UDP variants:** connected and unconnected, no bind, wildcard bind, explicit bind, sendto/sendmsg/sendmmsg/write, source-address control messages, GSO/corking, reconnect/disconnect, QUIC and multiple destinations per socket.
4. **Very short lifetimes:** send then immediately close/exit before userspace lookup; separately exec before metadata resolution. Verify complete identity or explicit unknown, never reused PID metadata.
5. **Transfer semantics:** fork before/after connect, exec with an inherited descriptor, cross-UID SCM_RIGHTS before/after UDP connect, simultaneous holders and simultaneous senders. Preserve the old expected results unless the spec explicitly approves replacements.
6. **Tuple collisions:** immediate port reuse between opposite-pinned and blocked apps, delayed queued UDP, SO_REUSEPORT and late/dropped destroy notifications. Assert zero wrong-app attributions.
7. **Namespace separation:** identical tuples in different netns, host-network containers, Flatpaks with identical executable paths, cgroup migration and a descriptor used from a different namespace.
8. **Async paths:** real io_uring execution, including worker execution, plus send paths outside the ordinary sendmsg route. Identify unsupported paths explicitly.
9. **Startup and restart:** sockets existing before attachment, applications starting during identity seeding, engine crash/restart and partial hook attachment. Inspect actual surviving attachments before crediting cleanup.
10. **Pressure and loss:** full cookie/tuple/process maps, metadata byte cap, ring-buffer exhaustion, allocation failure, stale/conflicting entries and delayed reclamation. Exercise live legitimate sockets alongside the faults.
11. **Deployment constraints:** missing BTF, cgroup-v1 configuration, denied capabilities, lockdown/Secure Boot, enforcing SELinux/AppArmor, and an existing cgroup firewall.
12. **Full stress:** the 65,536-flow cap, 9,004-lookup storm and reported 11,532-lookup handshake window, plus the 20,000-UDP-session overload. Record actual denominators, unique attempts, retransmissions, backend use and all resource peaks.

The namespace harness can drive real hooks and maps on its host kernel. A container or netns does **not** supply a different kernel: actual 5.8 coverage and distinct distro-kernel coverage require VMs or appropriate runners. Test x64 and arm64; fentry on a recent x64 CI host does not establish the floor.

Prove the chosen backend was active. Do not allow an attachment error followed by fallback to produce a green “BPF” test. Read case counts and failures even when a diagnostic workflow continues after errors. Use repeated independent runs with fixed documented load, not silent retries until green.

## 8. Proposed changes to the locked design and gates

These are recommendations for an explicit design amendment. `SYSTEM-DESIGN.md` remains unchanged.

### §5.6

1. **Define ownership:** choose recorded TCP initiator and first UDP-session sender, or retain live holders. State the treatment of inactive second holders and later conflicting senders. A creator-only rule is not acceptable.
2. **Select backend explicitly:** BPF observation when the required capability set works; diagnostic/proc fallback otherwise. Expose actual backend, degraded reason and coverage.
3. **Specify lookup joins:** packet tuple → socket cookie and process/executable generation → complete app identity. Use diagnostic-cookie lookup and then the current validated holder search as secondary paths.
4. **Preserve unknown policy:** absent, incomplete, conflicting or unverifiable evidence remains unknown and follows §5.4. Kernel collection never drops traffic merely because a map update fails.
5. **Specify identity history:** PID/start protection, exec generation, metadata validity, bounded post-exit retention and startup reconciliation. An event's creator cgroup is never sufficient app proof.
6. **Keep one deadline:** all map lookups, metadata waiting and fallback work share the existing 10 ms budget. Do not give every backend another 10 ms.
7. **Specify lifecycle and budgets:** attach before capture, retain ownership through queued first packets, coexist with other BPF programs, and account for kernel allocations.

Related amendments would be needed to §2/service hardening, §5.3's UDP identity integration, §5.9's memory accounting, §8's dependency/licensing list and §10's compatibility matrix. Retain the existing UDP cookie destruction/reconciliation protection until the replacement, if any, is separately proven.

### Gates

**Keep p95 below 10 ms and at least 99.5% complete, correct ownership in each required stress window.** Do not replace the rate with “BPF map hit rate” or exclude fallback misses. Report p99 and maximum as well, with total deadline overrun counts.

Measure from first-packet arrival at the engine through a validated, policy-usable identity, including queueing/enrichment/fallback. Also measure syscall/packet-path overhead and end-to-end connection setup, so moving work into BPF cannot make an expensive design look faster.

Add separate gates for:

- **Correctness:** zero wrong-app results in all identity, reuse and namespace tests. A wrong known owner is worse than a counted unknown.
- **Coverage:** cold TCP and UDP, IPv4/IPv6, short-lived senders, inherited/passed descriptors, restart and async-I/O cases. Keep deliberate ambiguity tests separate from ordinary unambiguous traffic, with explicit expected outcomes.
- **Capacity:** no unreported map insertion loss, metadata loss or eviction; bounded kernel and userspace memory after repeated churn; existing flows continue under overload.
- **Backend honesty:** exact hook set, attachment health and per-backend counters recorded. Forced fallback is tested separately, with the same guarantee unless the spec expressly adopts degraded performance.
- **Performance:** retain §10's no unexplained regression above 10%, including CPU per GB and end-to-end latency. Include application-side and kernel costs.
- **Compatibility:** actual floor kernel on both architectures and the supported distro/security-policy combinations. No silent “skip” for a required hook.

The current scoped gate also checks that cgroup hints were populated for 99.5% of lookups. BPF fast-path lookups need not perform that operation. Replace that implementation-specific assertion only with evidence of the selected backend's real coverage; do not remove the identity or line-selection assertions. Recompute old and new results over the same attempts.

For counters, retain timeout/missing/ambiguous totals and add capture failures, unrecognised task context, metadata incomplete, tuple collision, stale generation, map-full, event loss, backend hit/fallback, attach failure and latency by phase. Avoid combining fundamentally different causes into one “not found.”

## 9. Decision boundary

**Should we switch the primary architecture? Yes, conditionally: event capture plus the existing fallback is the stronger design for sustained churn.** It removes the repeated descriptor-discovery dependency and preserves evidence that a later scan cannot recover.

**Does recording socket creation/connect alone satisfy the question? No.** Complete UDP coverage, executable/app identity, startup gaps, namespace separation, map pressure and sharing semantics remain essential.

**Can the present scanner realistically reach 99.5%?** On selected workloads and machines, yes; the reported steady passes support that. Reliable passes in all the supplied storms are not demonstrated, and the handshake window needs roughly an eightfold reduction in misses on the supplied denominator. I would require direct phase evidence and repeated margin before betting on further tuning. No amount of tuning recovers ownership history that no longer exists.

**What has not been proved here?** BPF accuracy, measured CPU/memory/binary size, complete short-lived app identity, all UDP/async paths, and distro/security-policy compatibility. This study supplies source-backed design constraints and a testable proposal, not benchmark results or permission to alter the locked contract.
