# M4 PR 2a: Control's native engine client

2026-10-24. This is the first of the two production-cutover PRs in the M4 plan.
It teaches Control the native engine's contract (spec §5.10) and the restart,
probe and accounting rules the earlier native PRs left "for the cutover". The
ordinary build still runs the M2 stand-in; the tag drop, the stand-in refusal
and the lifecycle-suite port are PR 2b.

## Dialect

Control's engine client (`internal/lifecycle/remote.go`) dials the engine's
pipe the way the installation says: the native install (recorded with the
service) gets the native dialer, which sends no M2 impersonation primer byte,
because the native host's pipe carries plain newline JSON and rejects that
byte on the first exchange. It then chooses its wire dialect from the hello
capabilities. `singbox-adapter-v1` selects the temporary
adapter payload, unchanged. Anything else must advertise `revisions`, `lease`,
`status`, `paged-totals`, `totals-ack`, `terminal-stop` and `probe-options`,
or attach is refused with the missing capability named. The adapter dialect is
deleted with sing-box in PR 4.

The native revision is compiled from Control's policy: a line binds by its
alias (the same identity the sing-box adapter used), shares become integer
weights, lanes and the blocked set are copied, and shares of blocked lines are
dropped as spec §4.6 already forbids them. A pin binds exactly the identity the
user selected (design decision recorded in the spec). The engine's identity
travels end to end: flow records carry `AppID`, Control's app tracking keeps a
sandboxed app's identity beside its display path, and the pin API stores that
identity (`flatpak:`, `snap:` or `appimage:`) instead of the shared path. A
path pin becomes the platform's own normalisation (Windows folds case, Linux
keeps it), which on Windows is the engine's identity, so 0.3.x pins and the
API behave exactly as today. On Linux a path pin inside a sandbox location, or
for an app the engine reports under a sandbox identity, is kept and shown as
needing reselection (`pinNeedsReselection` on its state row) and compiles to
nothing: it is never routed by guess, and never auto-converted, because two
sandboxes can share a path. Nothing is inferred, and the compiled hash depends
on the durable revision alone. The
engine's hash of that config is what the engine checks; the acknowledgement
Control records carries Control's own revision hash plus the engine's apply
point. An engine already loaded receives `apply`; `start` is only for a fresh
instance. A refused start keeps the connection: the engine's status, not the
transport, is what Control classifies.

Snapshots are synthesised from the fixed-size native `status`: policy fields
come from Control's durable desired revision when the engine has loaded exactly
that revision, the PID is the child's, and `StartedWith` is the loaded policy.
Flow records keep the `Chains[0] = "line-<id>"` shape every Control consumer
reads. A flow's `Host` is its destination address only once the upstream
connection is established (spec §4.5, "2 different hosts" means established
destinations); a connecting flow lists its line but is never evidence.

## Exit classification and restart budget

A stopped engine is classified through the service manager's status, which
already folds the shared outcome reader: `Cleanup`, `ExitKnown`, `ExitCode`
and the instance's outcome file. Only exit 3 with completed cleanup and the
engine's own "adapter lost" reason is adapter loss; a lease expiry or a
verified clean stop (exit 0, cleanup complete, reason "stop") is routing off;
everything else is a failure. The supervisor journals a counted failure or
loss before the restart it allows, and holds the restart back while that
write fails. While the manager reports cleanup pending,
Control polls for up to 10 s before classifying; past that it counts the exit
as a failure and says so in the log. Nothing is guessed clean. The same
classification runs at Control startup for a native engine that stopped while
Control was down, so that failure or loss counts (deduplicated by the journal's
last failure id) and is journaled before the restart it allows. Control
acknowledges the engine's service-initiated stop record, so adapter-loss
cleanup does not wait out the 2 s delivery timeout.

Core keeps a ten-minute window of clean adapter losses beside the crash budget
(both durable in the control journal, both cleared by a fresh routing intent).
The first three losses restart at once and leave `failures` alone; the fourth
and later go through the ordinary 1/2/5/30 s backoff and the five-failure
latch (spec §5.1 and §2). Closure cutoffs are apply points: the native
acknowledgement's point is recorded on each intent and sent as `startedBefore`
with the line closure; Reconnect closes by native flow ids. Every closure is
bound to the engine instance Core checked it against: the client captures its
session under one lock, refuses the request if that instance is no longer
attached, and sends the intent's instance and epoch so a replacement attached
in between is fenced by the engine itself (flow ids are reused per instance).

The engine service's only failure action is the recovery command on Windows
and `ExecStopPost` with `Restart=no` on Linux. A pure Linux test reads the unit
text and the installed proof reads the real recovery actions, so no manager
ever respawns the host: Control owns every restart.

## Probes

Every probe result carries its `kind` and the engine instance that answered.
Control accepts a result only when the kind matches what it asked for (a quick
pass never restores a line that needs the full HTTPS check) and the instance is
still the current one; anything else becomes `engineUnavailable`, which changes
no line's state. The in-process sing-box adapter and the adapter dialect stamp
the same two fields, so the rule applies to every engine.

## Exact accounting

Every five seconds while routing is on, Control reads all pages of `totals`
under one receipt within the engine's ten-second snapshot lifetime, absorbs
them into a routed-usage record keyed by identity and generation, writes
`usage.json` through the existing atomic store (temp file, fsync, rename, parent
sync), and only then sends `ackTotals {opId: "ack-" + receipt, receipt}`. The
record keeps the engine's cumulative counter as a high-water mark per
generation, so a crash between the commit and the ack re-reads counters at or
above the marks (no double count), and a crash after the ack sees retired
identities return with a new generation (no loss). A new engine instance drops
every mark. Identities the engine no longer reports fold into an `other`
bucket beyond 4,096 kept entries; present identities are never folded. The
record stays dirty until a write succeeds, so an unchanged read after a failed
commit still writes before it acknowledges. Every `usage.json` writer (the
minute timer and the accounting consumer) takes the snapshot and writes under
one lock, so an older snapshot never replaces a newer, acknowledged one. The
routed section is reloaded with exact integers, not the record's float64 path.

Caps keep counting the whole adapter, as 0.3.x does (spec §4.6, "today's rules").
The exact routed totals are stored for the desktop work in milestone 5 and have
no UI consumer yet; `/api/state` is unchanged.

## Proofs

Pure tests (fail on main's code where noted):
- `internal/lifecycle`: attaching to a real native `protocol.Server` over an
  in-memory pipe (main refuses it: "engine swap is not installed"); the
  translated revision is deterministic and compiles; start/apply carry points;
  flow records keep the chain shape and only established hosts; line closure
  by point spares newer flows; probe kind and instance on the wire; paged
  totals and an idempotent acknowledgement; exit classification; adapter loss
  reaching the snapshot after the service stops.
- `internal/control`: three free losses then the fourth counts, durable window,
  cleared by a fresh intent; `acceptProbe` rejects a mismatched kind or a
  superseded instance; a quick-only engine never restores a down line; cutoffs
  recorded and sent as points; the totals consumer over a real flow table with
  crashes between commit and ack and between ack and read, exact to the byte;
  no ack without a durable commit; the adapter-era `usage.json` keeps its shape.
- `internal/usage`: generation and instance arithmetic, compaction, file round trip.
- `internal/service` (Linux): the engine unit never restarts itself.

Installed proof (`TestNativeControlCutover`, fault build, Windows x64/ARM64 and
Ubuntu 24.04/26.04 x64/ARM64), every subtest a required PASS line in
`scripts/run-native-proof.mjs`:
- sign-in through the installed Control starts the native engine and carries
  real TUN traffic;
- the engine service has no manager restart action;
- exact usage: 65,536 echoed bytes, a Control crash at the commit barrier (the
  record already holds the bytes), reattach to the same instance, no double
  count across two further rounds, a crash at the ack barrier, then totals
  exact to the byte;
- a killed child counts exactly one failure and routing returns on a new instance;
- four injected adapter losses through the real read pump: on Windows the
  genuine Wintun removal error exits 3, three are free and the fourth counts.
  The Linux engine has no clean adapter-loss outcome at all (the exit-3 path
  exists only in `internal/engine/windows`; spec §5.1's rule is written for
  Wintun removal and the helper's death), so there a failed read pump is an
  ordinary failure: the proof requires each to count, the fifth to latch, and
  the owner's explicit retry to clear the budget;
- Control absent past the lease (recovery disabled), the engine fails open,
  then a Control start restores wanted routing within 70 s.

Local validation was limited to `go vet` and the pure tests of the changed
packages at Idle priority on two cores; all installed behaviour is hosted-only.
