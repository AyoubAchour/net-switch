# Linux 1.0 release blockers

PR #36 delivers the Linux platform and the fallback owner scanner. It does not
qualify the engine for the 1.0 release. The design decision recorded in
SYSTEM-DESIGN §5.6 on 20 October 2026 moves Linux attribution to eBPF
initiation/send records, with the scanner as a
fallback. See the [source-backed study](linux-owner-ebpf-study.md).

Attribution assertions in all thirteen overload cases and flow pagination are
deferred. Each overload still requires **99.5% successful lookups** in its own
non-injected window. Pagination still requires **299 identified rows out of 300**.
The real numerator, denominator and threshold result remain in the JSON, console
log and summary. Every declaration carries `release-blocker` status, including
when a sample meets its threshold. No retry or excluded natural miss changes it.

The current measurements below are from head `045842f`, ARM26 full run
[39434095158](https://github.com/AyoubAchour/net-switch/actions/runs/39434095158).
They describe the unchanged checks before the expanded classification. They
are not final-head release qualification.

| Case | Natural misses / lookups, or identified rows | Original attribution check |
| --- | ---: | --- |
| overload.udp-sessions-per-app | 9 / 10,004 misses | Met |
| overload.udp-sessions-total | 120 / 16,390 misses | Failed |
| overload.tcp-connection-storm | 82 / 9,004 misses | Failed |
| overload.tcp-handshakes-in-flight | 58 / 11,331 misses | Failed |
| overload.tcp-flows-total | 1,025 / 65,536 misses | Failed |
| overload.tcp-buffer-budget | 3 / 64 misses | Failed |
| overload.rejection-notices-per-app | 0 / 12,000 misses | Met |
| overload.rejection-notices-total | 121 / 25,600 misses | Met |
| overload.timewait-cap | 0 / 5,060 misses | Met |
| overload.udp-pending-bytes | 0 / 4 misses | Met |
| overload.unknown-owner-limits | 0 / 3 misses | Met |
| overload.tun-write-queue | 0 / 4 misses | Met |
| overload.memory-at-limit | 11 / 86 misses | Failed |
| protocol.flows-pagination | 298 / 300 identified; requires 299 | Failed |

Deliberately injected misses remain separately reported: 132/132 in pending
bytes, 3,000/3,000 in unknown-owner limits and 131/131 in memory pressure.

All other assertions remain mandatory in PR CI: actual capacity reached, memory
and byte budgets, independent server observations, stream survival, correct lanes,
cleanup and the steady lookup gates. The per-app capacity fixtures must still
actually fill the identified app's cap; otherwise they have not tested that
limit. Unknown pool sizes and accounting remain hard capacity checks. An ordinary
failure in a deferred case still fails the job. Fault cases keep their separate
build. The terminal/app-scope gates remain hard in both serial and ten-at-once
phases.

Mixed identity/routing checks are split. Small TCP probes exchange one response
with the existing stream server and keep the socket open for a flow snapshot;
UDP probes keep their existing socket and datagrams open for the same inspection.
Counts, sequential TCP admission and connection deadlines are retained. Every
probe's own server observation must match its exact identified or unknown flow.
Wrong nonempty identities and wrong lines still fail; unknown flows must use the
main lane. Stream identities are captured before the load, and every answer,
survival and silence limit remains mandatory afterward.

The probe/stream owner-known condition is a release blocker. Each split check
also reports whether its result would pass the original all-on-the-pinned-line
assertion. No server observation is discarded or silently retried.

The scanner remains a bounded fallback, reported as `proc-fallback` in owner
stats. Recent process observations can defer unrelated candidate scans for 5 ms
after a live owner is found. They never supply identity or prove absence, and
known positive hints always receive fresh validation. A previously unseen FD
transfer to another process can remain undiscovered during that window; the
fallback does not claim an exhaustive, simultaneous snapshot of all holders.

The **Acceptance** workflow's manual `release_gate=true` mode runs the separate
**Linux 1.0 release gate** check, with no engine workload:

```text
go run ./tests/linux/cmd/nsaccept release-gate
```

It inspects the complete source catalogue, accepts no case filter, and fails while
any declared release blocker or pending gate exists. It is separate from PR CI.
Removing a declaration requires the eBPF implementation and its acceptance
evidence; a green PR run or a lucky stress sample cannot clear it automatically.
