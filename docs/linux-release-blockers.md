# Linux 1.0 release blockers

PR #36 delivers the Linux platform and the fallback owner scanner. It does not
qualify the engine for the 1.0 release. The design decision recorded in
SYSTEM-DESIGN §5.6 on 20 October 2026 moves Linux attribution to eBPF
initiation/send records, with the scanner as a
fallback. See the [source-backed study](linux-owner-ebpf-study.md).

Attribution assertions in all thirteen overload cases and flow pagination are
deferred. Round 3 also declares the exact mixed-cap occupancy gate, making
**15 catalogue entries**. Each overload still requires **99.5% successful lookups** in its own
non-injected window. Pagination still requires **299 identified rows out of 300**.
The real numerator, denominator and threshold result remain in the JSON, console
log and summary. Every declaration carries `release-blocker` status, including
when a sample meets its threshold. No retry or excluded natural miss changes it.

The measurements below are from PR head `fb74394` (Go 1.27.3), Acceptance run
[39565641409](https://github.com/AyoubAchour/net-switch/actions/runs/39565641409),
on all four runners. Since then the branch was rebased onto main `9579039`;
on its own side only a scanner test fixture, the report's CPU-model line, the
workflow's failure-evidence step and this document changed. Each cell is natural misses /
lookups in the case's own non-injected window (pagination: identified rows of
300, 299 required). A threshold that a sample meets is still declared; a lucky
run clears nothing.

| Case | Ubuntu 24 x64 | Ubuntu 26 x64 | Ubuntu 24 ARM64 | Ubuntu 26 ARM64 |
| --- | ---: | ---: | ---: | ---: |
| overload.udp-sessions-per-app | 26 / 10,004 | 8 / 10,004 | 0 / 10,004 | 0 / 10,004 |
| overload.udp-sessions-total | 361 / 16,388 | 158 / 16,388 | 31 / 16,388 | 66 / 16,388 |
| overload.tcp-connection-storm | 2,007 / 12,304 | 1,275 / 12,604 | 289 / 12,904 | 559 / 12,853 |
| overload.tcp-handshakes-in-flight | 958 / 12,333 | 586 / 12,803 | 351 / 13,036 | 189 / 11,723 |
| overload.tcp-flows-total | 23,767 / 80,101 | 16,694 / 80,101 | 4,164 / 67,652 | 5,904 / 69,392 |
| overload.tcp-buffer-budget | 42 / 64 | 17 / 64 | 0 / 64 | 2 / 64 |
| overload.rejection-notices-per-app | 0 / 12,000 | 0 / 12,000 | 0 / 12,000 | 0 / 12,000 |
| overload.rejection-notices-total | 793 / 25,600 | 276 / 25,600 | 90 / 25,600 | 170 / 25,600 |
| overload.timewait-cap | 0 / 5,060 | 0 / 5,060 | 0 / 5,060 | 0 / 5,060 |
| overload.udp-pending-bytes | 0 / 4 | 0 / 4 | 0 / 4 | 0 / 4 |
| overload.unknown-owner-limits | 0 / 3 | 0 / 3 | 0 / 3 | 0 / 3 |
| overload.tun-write-queue | 0 / 4 | 0 / 4 | 0 / 4 | 0 / 4 |
| overload.memory-at-limit | 56 / 86 | 38 / 86 | 24 / 86 | 26 / 86 |
| protocol.flows-pagination | 286 | 293 | 300 | 299 |
| capacity.mixed-caps, held of 65,536 | 65,535 | 65,536 | 65,536 | 65,536 |

Held exact caps on the same run: TCP total held 65,536 on both ARM64 runners,
58,382 on Ubuntu 24 x64 and 65,455 on Ubuntu 26 x64. Those shortfalls (7,154
and 81), and the 1 missing in mixed on Ubuntu 24 x64, were each wholly
classified as unknown-overflow refusals. That is the only kind of shortfall
the catalogue allows; any other would have failed the job. UDP total, mixed
UDP, UDP per app and the TCP storm's identified 8,192 were exact on every
runner. Each runner ran 85 cases: 70 passed and 15 declared release blockers,
with no hard failures.

These checks stayed hard on every runner and passed:
- **TIME_WAIT probes:** all 50 alpha and 10 bravo post-burst probes were
  identified, with no misses in 5,060 lookups.
- **Live heap:** the largest forced-GC live heap was 412,428,664 B, against
  the 483,183,820 B limit.
- **Held sessions (§5.9):** an echo through every held UDP session in the
  per-app, total and mixed cases had a p99 of 1.9–10.1 ms (the limit is
  250 ms). Each full sweep took 0.27–0.98 s (the limit is 30 s). Every
  swept session kept its recorded engine flow ID, and no sweep admitted or
  refused anything.
The sweep also proves continuity: each swept session must still be the engine
flow recorded with the held pool (same flow ID for the same app source, so a
session recreated with the same outbound address and port fails), and the
sweep must make no new admission or UDP refusal.
The held-session check isn't an attribution check and isn't in the catalogue.

## Known fallback-scanner regression on slow x64 hosts (follow-up: eBPF task)

This is a regression in the `/proc` fallback scanner, tracked here on its own
so the attribution blocker can't hide it. **The eBPF attribution task owns
it:** it must settle it with a back-to-back A/B of the round-3 build
(`7c6692a`) and the current build on the same machine, before the scanner
becomes the fallback.

- **What:** in `overload.tcp-flows-total`, alone, on Ubuntu 26 x64, the
  round-3 code held 65,536 flows in 3 of 3 runs (15.6–17.2% misses on
  slow-cluster hosts, 12.9% on a fast one). The current code holds 65,536 on
  fast hosts; on slow-cluster hosts it misses 26–32% of lookups and holds
  about 56,200–61,200.
- **Where:** hosted x64 runners of one label land on different AMD CPUs, and
  scan cost splits into two clusters, about 8.5–10 µs and 12–14.6 µs per
  descriptor. The slow cluster was always seen on the EPYC 7763, and once on
  an EPYC 9V74 (the rebased head's Ubuntu 24 x64 run: 14.6 µs, 32.3% misses,
  56,185 TCP and 61,115 mixed held, all classified as unknown overflow), so
  it is a host condition, not only one CPU model. ARM64 runners are not
  affected.
- **Fixed in round 6:** per-read scan stamps allocated 438 MB in that case,
  27% of everything the engine allocated. Stamping only slow and running reads
  cut scan cost on the slow hosts from 14.4 to about 13 µs per descriptor and
  misses from 32.8% to 24–29%.
- **Ruled out:** restoring round 3's raw `/proc` opens on top of that made no
  difference (59,427 / 57,969 / 65,536 held). The descriptor-table
  reservation means those opens never grow the table.
- **Not explained:** CPU profiles of both builds show the same kernel
  readlink/getdents work in the scan, through a byte-identical syscall path,
  and less GC in the current build. No code path accounts for the remaining
  ~10% scan cost on slow-cluster hosts. Because each miss leads to more lookups,
  that small difference flips the held count there.
- **Now logged:** each acceptance report records the runner's CPU model
  (`cpu:` in the environment line), so every sample can be tied to hardware.

**Evidence** (GitHub Actions; the numbers above come from these):

- **438 MB / 27%:** [run 39552484899](https://github.com/AyoubAchour/net-switch/actions/runs/39552484899),
  artifact 12324389232, file
  `release/cases/overload.tcp-flows-total/engine/profiles-3733791922/heap.pprof`.
  This is the first TCP-total heap profile: 437,886,654 of 1,632,757,435
  allocated bytes are under `descriptorTrace.begin` (26.8%).
- **About 401 MB:** the focused baseline run 39561941930 shows the same
  allocation at about 401 MB. It is a different sample, not the same figure, so
  don't compare the two as if they were one measurement.
- **Comparison jobs (job ids):**
  - round 3: 119099278106, 119110362995, 119110378244;
  - baseline: 119095038905;
  - trace-out: 119095075114;
  - fixed: 119106885411, 119106899233;
  - raw-open: 119099228722, 119099246573, 119099265076;
  - rebased EPYC 9V74: 119193991061.

## Catalogue rules and hard checks

Deliberately injected misses remain separately reported: 132/132 in pending
bytes, 3,000/3,000 in unknown-owner limits and 131/131 in memory pressure.

The round 3 acceptance clarification separates actual admission limits from
occupancy lost to the fallback scanner. All capacity bounds, memory and byte
budgets, independent server observations, stream survival, correct lanes,
cleanup and steady lookup gates remain mandatory. An ordinary
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

The probe owner-known condition during load is a release blocker. Stream
identity is checked before load and is a hard requirement. Each split check
also reports whether its result would pass the original all-on-the-pinned-line
assertion. No server observation is discarded or silently retried.

Post-fault recovery is different: the three sequential probes after pending
overload, unknown-owner overload and a stalled TUN writer must all identify
bravo and use line b. Their identity and per-connection server checks are hard
PR failures, even though the enclosing overload case retains its declaration.
The sequential probes after the TIME_WAIT burst and handshake overload are hard too, as are other
route-recovery probes. A regression runs an unknown recovery result inside a
declared load case and requires the actual harness to fail the job.
The DNS-change survival precondition now also requires zero discarded streams;
its original no-retry verdict is an assertion, not only a diagnostic line.

The `capacity.mixed-caps` release target is 49,152 TCP flows and 16,384 UDP
sessions, alongside 4,096 retained TIME_WAIT endpoints. Every capacity fixture
requires live heap immediately after forced GC to stay at most 460.8 MiB
(90% of the 512 MiB `GOMEMLIMIT`). The capture precedes profile serialization.
Go-managed memory (`Sys - HeapReleased`), process RSS, kernel socket memory
and GC CPU share are reported, without gates. The previous managed-memory
verdict is also logged. Kernel socket pages use the kernel's aggregate
sockstat accounting, not an engine-only attribution. Bounds,
survival and each held TCP tuple's identity/route/server correlation are hard.
It reports baseline, UDP-only, UDP-plus-TIME_WAIT and mixed memory samples, so
the incremental cost per session, per flow and per retained endpoint is visible.

The total TCP cap fixture offers ten apps' 8,000 attempts, with the same
100 concurrent attempts per app, followed by a fixed 100-attempt sequential
tail from kilo. The tail always runs, even if the burst filled every slot.
It waits for pending admissions to drain. Kilo remains
below 8,192 even if all its 8,100 attempts succeed. No failed attempt is retried.
The burst-only held-cap and attribution verdicts are logged before the tail;
The original pre-tail 99.5% formula remains a measured release check as well
as the complete-case formula, so successful tail lookups cannot dilute it.

**Exact occupancy is deferred only with refusal evidence.** Shared admission
counters classify TCP and UDP decisions at the occupied budget under the
admission lock: total, UDP total, handshakes, app, UDP app, unknown, unknown UDP,
policy, or unexplained. A known app's refusal below all limits is unexplained.
No limits, timeouts, demand or scanner behavior change with this classification.

The hard checks require all offered attempts to be held or explicitly refused;
all admitted flows to remain held; engine flow counts to equal independent
client/server counts absolutely, not just as a delta: at the first sample the
engine's TCP and UDP counts must equal what clients and servers already held
(the survival stream, the settled burst, the held UDP pool), and at the second
sample that baseline plus the newly held clients, in every scope (total,
per-app, mixed, tail, TCP and UDP), so a phantom flow carried through both
samples fails; no failed outbound TCP dial or native UDP open; every forwarding
refusal to have the expected cap or unknown-pool reason; and every lookup miss
to be an unknown admission or counted unknown-pool overflow. Handshake, policy,
unexplained or unrelated app-cap refusals cannot waive an occupancy shortfall.
In the mixed case an app holding both protocols can legitimately reach its
8,192 combined cap before the total fills; that reason is also allowed, and
is subtracted from unknown-overflow credit. Each cap reason must have a matching
engine peak. Mixed per-app refusals additionally require a UDP-holding client
app to hold exactly 8,192 identified TCP and UDP sockets, as independently
observed by servers on that app's non-main pinned line. Unknown-owner sockets
on the main line never contribute to that per-app proof. Engine peaks alone
are not independent evidence. The TCP-only offer remains below every
app's cap and therefore accepts no per-app refusal.

Decision counters include repeated SYNs. Therefore the proof subtracts **all
allowed cap decisions** from the number of refused client attempts, even repeated
ones. The remainder is a lower bound on distinct unknown-overflow refusals. Only
when that lower bound covers the entire missing occupancy can the exact-count
check be release-only. An unexplained remainder fails PR CI. The old exact-count
verdict, real counts, reason counters, and lookup diagnostics are always logged.
Per-app UDP checks additionally retain each app's original exact-count verdict.

The tail runs while the large workload is still held. Its unknown lookup result
is deferred only alongside the same hard refusal accounting. Its old zero-miss
verdict stays visible. A timeout, failed dial, lost admission, or other refusal
reason fails hard. This does not apply to the separate post-fault probes after
the workload is removed.

Run 39489577354 at `db38712`, Ubuntu 24 x64 job 118858841217, is the motivating
failure: 19,673/80,001 burst lookup misses, 62,473 held TCP flows after the tail,
and 65,535 mixed flows. The old exact checks failed. That old binary had no reason
counters, so its failures cannot be retrospectively qualified by this rule.
New runs must supply the classification evidence. Demand is not raised again.

In the earlier x64 run
[39441805445](https://github.com/AyoubAchour/net-switch/actions/runs/39441805445),
the former 68,400 attempts produced 63,176 identified flows plus 2,048 unknown
flows: only 65,224 live flows. That run correctly failed the unchanged exact
65,536 cap/profile check. Increasing offered work lets the fixture exercise
capacity despite the separately reported attribution defect. That historical
offer increase is retained; resource, refusal, survival and cap bounds stay hard.

The per-app TCP storm likewise offers 12,000 fixed attempts, still 300 at a time
and without retries. Run [39461404148](https://github.com/AyoubAchour/net-switch/actions/runs/39461404148),
Ubuntu 24 x64 job 118761521489, offered 9,000 and held 8,153 identified plus 847
unknown flows, with no refusals. It correctly failed: it had exercised neither
the exact 8,192 identified cap nor refusal at that cap. The larger offer exceeds
the identified and unknown pools combined; both pool limits,
the three-second refusal bound and stream survival remain mandatory. Reports
state the offered count; the failed 9,000-attempt sample remains a failure.

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
