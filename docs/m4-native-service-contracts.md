# M4: native service contracts, first part

2026-10-22. This is the first reviewable part of the native-contracts PR in the M4 plan. Control's production cutover is still separate.

## Scope

The `m4_native` build uses the native runtime through the installed `netswitch-engine service` entrypoint and Ctl cleanup. Ordinary builds retain the M2 stand-in until the Control cutover. Selection is compile-time; there is no runtime fallback. The temporary tag goes away at cutover.

The native service shares runtime construction, authenticated transport and cleanup with standalone acceptance. Native ownership locks remain the exclusion boundary. The service supplies readiness and resume notifications and serializes epoch/revision history into one durable record. A restarted engine reports no loaded revision until start; an in-progress start does not report a loaded policy before capture succeeds. Old stand-in state is rejected here, pending the separately reviewed migration.

SCM and command exits retain the direct native outcome: clean adapter loss is 3, ordinary failure is 1, and an unrecovered Go panic remains 2. Joined cleanup errors cannot inherit the clean-loss code. Service status reports whether its final exit code is known. A terminal message is still provisional: Control's terminal handling and restart budget belong to the cutover.

## Totals

The maximum-cardinality test admits and closes 65,536 distinct 512-byte app identities across 255 lines. The old single reply exceeds 1 MiB by more than thirty times. This is measured from real flow-table accounting, with no fabricated oversized diagnostic field.

`totals {cursor}` now returns `{apps, lines, count, cursor?}`. Each page has at most 64 aggregate entries. The first call freezes the counters, including closed flows; later pages read that same snapshot. `count` is the total number of app and line entries. A missing cursor means completion. Both existing native acceptance clients consume and validate the full sequence.

Totals share the flow snapshots' four-slot, ten-second and byte reservations. Aggregation memory is reserved before copying. An exhausted budget or expired cursor is an error; no accounting is truncated or evicted. A caller must discard an incomplete poll. `stats` remains separate and bounded. The underlying lifetime counters are unchanged; this change bounds snapshot work and wire replies, not the number of distinct identities that can accumulate over an engine's lifetime.

Tests cover maximum cardinality, escaped IDs, completed-between-poll traffic, a flow closing after the first page, concurrent new traffic, expired cursors, cross-kind snapshot budgets and controller fencing. The fixture logs both the old reply size and the largest new page.

## Installed service proof

`native-service-contracts.yml` runs Windows x64/ARM64, Ubuntu 24.04 x64/ARM64 and Ubuntu 26.04 x64. Each job builds and installs two native candidates in separate directories: one without fault hooks and one with `lifecycle_test`.

The suite records each binary's version/hash, checks the running service image and PID, and uses the real root/SYSTEM engine connection. It also verifies that another OS user is denied while the engine service is live. Tests exercise start/apply/status, stale/conflicting revisions, stable apply points, reattachment/fencing, old-flow closure with newer-flow survival, totals, historical state after restart, graceful stop, lease expiry, an actual service crash and native Ctl/SCM/ExecStopPost cleanup. Capture and held traffic are established before any cleanup is credited.

The build without fault hooks is given an arm file and must continue forwarding without producing a hit record. The installed fault build has two observations:

- **Forwarding-only stall:** stop the real TUN read pump after it receives a packet. Require blocked traffic for at least 22 seconds while renewal/version rounds still answer within three seconds. Verify capture still exists, release the fault, and verify the same stream resumes.
- **Whole-service stall:** suspend the actual service process. Require its held stream and IPC to stop answering while SCM/systemd still reports that same process running, for more than the 30-second lease. Verify capture still exists. Resume without sending renewals and require lease cleanup and direct traffic to recover.

These tests record `M4_STALL` evidence. They intentionally measure the current fault domains; they are not a watchdog detector or a claim that native recovery already meets M2's guarantee. The coordinator reviews the hosted results before detector design. A separate watchdog process requires an architecture decision before implementation.

All runtime proofs are hosted-only. Local validation is limited to builds and pure unit tests at Idle priority, with the pinned Go toolchain, two cores and `-p 2`.

## Sequential follow-up

The original native-contracts scope is split to keep each PR near the requested review limit. After this part is reviewed and merged, branch again from main for custom probe parity, the bounded loopback-only test proxy and its product-off proof, and missing-line/churn primitives. Complete remaining native state/final-outcome integration and the agreed watchdog work before the Control cutover. No branch stack is needed.

The Linux attribution/eBPF work remains separate. M4 is not complete until the Linux release gate passes. Frozen Node modules and fixtures are untouched; the removal check and its enumerated oracle exceptions come in the later removal PR.

References for service outcomes/readiness: [Microsoft service status](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/ns-winsvc-service_status_process), [systemd service types and cleanup](https://www.freedesktop.org/software/systemd/man/latest/systemd.service.html). Product behavior and the M4 gate are recorded in the locked system design.
