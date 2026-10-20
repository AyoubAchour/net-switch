# Linux 1.0 release blockers

PR #36 delivers the Linux platform and the fallback owner scanner. It does not
qualify the engine for the 1.0 release. The design decision recorded in
SYSTEM-DESIGN §5.6 on 20 October 2026 moves Linux attribution to eBPF
initiation/send records, with the scanner as a
fallback. See the [source-backed study](linux-owner-ebpf-study.md).

Only the ownership-success assertion in these three loads is deferred:

- `overload.tcp-connection-storm`
- `overload.tcp-handshakes-in-flight`
- `overload.tcp-flows-total`

Each still requires at least **99.5% successful lookups** in its own non-injected
window. The real numerator, denominator and threshold result remain in the JSON,
console log and summary. They carry `release-blocker` status, including when a
single sample meets the threshold. No retry or excluded natural miss changes it.

All other assertions remain mandatory in PR CI: actual capacity reached, memory
and byte budgets, independent server observations, stream survival, correct lanes,
cleanup, steady lookup gates and identified pagination rows. An ordinary failure
in a deferred case still fails the job. Fault cases keep their separate build.

The **Acceptance** workflow's manual `release_gate=true` mode runs the separate
**Linux 1.0 release gate** check, with no engine workload:

```text
go run ./tests/linux/cmd/nsaccept release-gate
```

It inspects the complete source catalogue, accepts no case filter, and fails while
any declared release blocker or pending gate exists. It is separate from PR CI.
Removing a declaration requires the eBPF implementation and its acceptance
evidence; a green PR run or a lucky stress sample cannot clear it automatically.
