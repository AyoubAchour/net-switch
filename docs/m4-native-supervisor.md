# M4 native supervisor

## Adapter removal: PnP and IP absence

ARM64 job 120593984006 resolved the remaining failure: by 511 ms the PnP
device, both IP-interface entries and all addresses were gone. The same-LUID
NDIS row stayed Down for 30 seconds. The inventory found no Wintun handle;
the surviving endpoints were system-owned TCP TIME_WAIT records. Waiting for
that row made stop depend on other applications' closed connections.

x64 job 120593984157 failed at loaded stop with the same confirmation error.
Its final-quit samples still show the same Down LUID, absent PnP, no addresses
and both IP entries not found through 30 seconds. The final-quit inventory
reported zero TCP/UDP endpoints in both families; that later snapshot does
not establish a larger TIME_WAIT count after the fill. Neither endpoint
counts nor a hypothesized kernel reference is used as ownership authority.

The decision recorded in the spec is now shared by retirement and creation:
no present matching Wintun devnode and ERROR_NOT_FOUND or ERROR_FILE_NOT_FOUND for the recorded LUID
in both IP families means absent. NDIS status is not consulted. Unknown or
different LUIDs, a foreign GUID using our alias, and query errors refuse the
operation. Confirmation retains its five-second cap and the caller deadline.

[GetIpInterfaceEntry](https://learn.microsoft.com/en-us/windows/win32/api/netioapi/nf-netioapi-getipinterfaceentry)
distinguishes a missing address family from a LUID that no longer exists;
both are absence. An unreadable foreign Wintun registry key is skipped only
when its exact `SWD\WINTUN\{GUID}` instance ID proves a different GUID.
Uncertain or matching identity fails closed with the device named in the error.

A small atomic, boot-bound adapter identity file beside the journal preserves
the last created LUID after journal compaction and across engine process exit.
It is written under the lifetime lock before adapter creation is acknowledged;
failure rolls back through the existing journal. It is historical evidence,
never authorization to remove a live device. Missing history cannot authorize
the create guard to ignore an existing row. Recovery alone, under the lifetime
lock and a durable adapter record, can recover a missing/stale LUID from an
exact-GUID row plus the exact present SWD instance and matching registry GUID.
It persists that identity before removal and rechecks the device identity at
removal. With no present device, a lingering exact-GUID row may supply history
only when both IP families are absent. Alias collisions, ambiguous rows and
query failures still refuse. In-process live adapters retain strict LUID
matching. Corrupt history is logged and treated as missing; a failed history
write never advances the in-memory identity or retires the journal intent.
The 20-cycle harness captures the row immediately
before the next create, checks PnP/IP re-arrival, and reports LUID reuse.

On c2ebd23f, acceptance artifacts 12530156353 (ARM64) and 12528636617
(x64), `server-output.log`, each contain 25 adapter arrivals. The initial
arrival has previous_luid=0 and reused=false; all 24 subsequent arrivals on
each architecture have reused=true, LUID 14918723538255872. Thus 48/48
re-arrivals reused the recorded identity, including all 20 cycles per runner.
Retain the single recorded LUID; no set of historical LUIDs is needed for
the observed behavior. An unrecognized different LUID continues to fail closed.
Routing-off min/median/max was 95/107/259 ms on ARM64 and 109/133/225 ms
on x64, comfortably within the stop budget.

The follow-up reference inventory is read-only. When PnP is absent but the normal row remains,
the harness starts a separate eight-second inventory helper. It reports the
matching host/child/registrar/harness process tree, system handle object IDs,
file-object names, and both families' owning-PID TCP/UDP endpoints bound to
the TUN addresses. Device instance, physical object name and interface paths
are recorded before close. Handle-table/name reads are racing snapshots, not
ownership authority. Remote name queries temporarily duplicate handles and
can therefore delay removal themselves; their interval is explicitly logged
and the helper is killed at its bound. Do not attribute removal latency during
that interval to the engine. Endpoints retain exact counts with 256 details
per table; handle inventory stops with an explicit incomplete error at 8192
selected handles or 64 MiB of system table. A blocked name query is reported
as incomplete, never as no surviving handles.

At the first 250 ms of a lingering row, a trace-only engine snapshot records
TCP submitted/completed I/O, live registrations, pending OVERLAPPED state,
UDP registrations, socket handle IDs and live goroutines. TryLock failures
are recorded rather than blocking cleanup; details and stacks are bounded.

Code audit: `Engine.stopLocked` cancels flows and joins TCP, UDP, TUN pumps
and the session before journal cleanup. `socketWatch.Detach` waits for the
CancelIoEx completion before unpinning; UDP detaches WSAEventSelect before
closing its socket. The completion port and UDP shard workers themselves
remain until `shutdownTail.finalize` calls `Dialer.Close`, after runtime Stop.
Their existence alone does not prove a live socket: both pool close functions
refuse live registrations. The registrar owns the only explicit Wintun device
open in product code, and session close joins its process exit.

One additional surviving reference is concrete in the supervised path:
the host retains its connected, TUN-bound health UDP socket until the entire
supervisor returns. Non-running status clears cached index/port but does not
disconnect that socket. It is a candidate for installed-service teardown, but
cannot explain standalone acceptance, which does not start the supervisor.
This is distinct from the now-measured standalone TIME_WAIT case.
[Microsoft's surprise-removal contract](https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/handling-an-irp-mn-surprise-removal-request)
confirms that an open device handle can prevent the final remove IRP.

ARM64 job 120561072134 joined the session in 69 ms but exhausted the
five-second IP Helper confirmation. This disproves session retirement as a
complete explanation of the remaining failure. No new absence criterion is
claimed proven by that log.

Main and this branch use the same fixed GUID, alias, and normal IP Helper
table for the creation guard. Main does not confirm table disappearance at
stop; its acceptance driver waits for the engine process to exit before the
next start. That provides another teardown boundary, not another identity.
The later inventory establishes that no application device handle survives.

The hosted acceptance helper now samples the normal and raw interface views,
all eight status flags, operational/admin/media state, GUID, alias, type,
present PnP nodes, IPv4/IPv6 IP-interface lookups and unicast-address counts.
Its first sample precedes cycle-one stop, the loaded stop and final quit. It continues every
500 ms until both table rows disappear or 30 seconds pass; an outer 35-second
kill bounds a stuck Windows query. This is a separate read-only process, so
sampling neither delays service cleanup nor changes its success criterion.
Stop assertions remain strict. No replacement is created while the
observer is collecting the post-stop samples.

[Wintun's close path](https://git.zx2c4.com/wintun/tree/api/adapter.c)
closes the software device, removes its device instance and queues orphan
cleanup. [Microsoft's SwDeviceClose contract](https://learn.microsoft.com/en-us/windows/win32/api/swdevice/nf-swdevice-swdeviceclose)
explicitly says removal is asynchronous; a subsequent software-device create
is queued behind removal. That does not authorize bypassing our pre-create
ownership guard. [GetIfTable2Ex](https://learn.microsoft.com/en-us/windows/win32/api/netioapi/nf-netioapi-getiftable2ex)
returns the same set of interfaces in normal and raw modes, but obtains their
state from the filter-stack top versus the interface itself.
[Disconnected or down flags](https://learn.microsoft.com/en-us/windows/win32/api/netioapi/ns-netioapi-mib_if_row2)
alone cannot establish absence. The measured PnP-plus-IP criterion above is
applied consistently to both paths; query errors never count as absence.

The `m4_native` service now hosts one verified native child. This implements
option (e), recorded in spec §3.4. Control's client, restart/backoff/latch
policy and exit classification are in [the production cutover](m4-production-cutover.md).
The host never respawns a child.

Explicit protocol Stop now owns its cleanup failure report. A failed stop
first writes the error reply through the unbuffered transport, then reports
fatal cleanup failure to the service. A disconnected or stalled reader cannot
prevent exit: the same notification has a two-second delivery bound. The
outcome file remains authoritative for final cleanup/exit classification, but
does not replace the immediate error reply. Adapter-loss and lease terminal
paths keep their existing reporters.
The host also gives failure exits the existing bounded 500 ms public-relay
drain; previously only clean exit 0/3 received that opportunity. Forced kills
still cancel immediately, and cleanup/exit classification is unchanged.

## Ownership and transport

The host keeps the public endpoint, its existing root/SYSTEM ACL and native
newline framing. The reported engine PID belongs to the child; the public peer
PID belongs to the SCM/systemd host. The child alone holds the native lifetime
lock, protocol epoch, revision, operation cache and genuine Control lease.

Windows uses the reviewed atomic `winchild` launch. Its one-process job refuses
ordinary descendants. The registrar is still the sole reviewed breakaway,
atomically assigned to its own UI-restricted, one-process, kill-on-close job.
The host retains the registrar's SYNCHRONIZE-only capability before resume.

Linux executes the running `/proc/self/exe` inode, verifies the child's image
and inherited service cgroup, and retains a pidfd for termination. The launching
goroutine stays on its OS thread until child exit: Pdeathsig follows that thread.
Go's launch code sets SIGKILL and checks for parent death across the fork/exec
window. The child verifies its parent and retained death signal before opening
the engine. No credential/file-capability transition is introduced.

The private protocol listener checks the exact host PID. Windows uses a fresh
protected pipe name; Linux uses a root-owned 0600 socket under `/run/netswitch`.
Its fixed name is reclaimed only under the child's native lock, with the same
socket-owner/type/live-listener checks as the existing native endpoint.
Inherited unidirectional pipes carry only bootstrap, readiness, registrar,
power, health-state and final-outcome messages. They never accept public RPCs.

Four public connections each have two queued frames in each direction, plus
one reading and one writing frame. Frames retain the existing 1 MiB ceiling:
at most 32 MiB of live relay frame storage across the host. A queue still full
after one second closes that peer; replies and accounting are never silently dropped.
Private messages have separate eight-slot queues and a 16 KiB frame ceiling.
Each log sink has 64 records of at most 4 KiB. Dropped host logs are recorded in
the outcome. Standard and gVisor child logging use the bounded sink.

## Forwarding check and recovery

The host reserves one UDP socket before launching the child and keeps it for
the lifetime. Application port exhaustion cannot consume it later. It sends
nothing until bound to the child's verified TUN index and connected to its
private peer. Linux uses SO_BINDTOIFINDEX; Windows uses IP_UNICAST_IF.

The child opens an echo endpoint inside gVisor at the existing TUN's peer
address, 198.18.0.2. A valid request must come from the TUN address 198.18.0.1
and carry the 256-bit key delivered over inherited pipes. Each host challenge
also has a fresh sequence. The response crosses the real TUN read pump, UDP
network stack, output queue and TUN write pump. It needs no live internet line.
The UDP queues are 4 KiB; stale replies cannot satisfy a later challenge.
The endpoint exists only for a supervised child and is not the §5.11 test proxy.

The host starts checking at readiness, with three seconds per probe and an
18-second continuous-failure window. Healthy forwarding resets the window.
Only running, loaded forwarding is judged. Starting has a separate 35-second
deadline (including the registrar's 15 seconds); stopping has 20 seconds.
An idle error has no lifecycle deadline while the lease is live, just like off;
Control's backoff/latch may keep it idle indefinitely. Lease expiry still ends
the child. Starting and stopping lifecycle
deadlines terminate directly, without adding another forwarding-failure window.
Off means no forwarding is requested; a responsive status/renewal never proves
active forwarding health. A change of start timestamp, epoch, index or port
rebinds/reconnects the reserved socket; it is not a child failure.
Awake clocks, resume grace and the bounded two-minute suspend pause are retained.
The child receives real resume events; the host never synthesizes renewals.

A failed window forces verified termination immediately, without a graceful
stop delay. The host joins child/registrars, then takes the released native lock
for journal cleanup. A shared six-second teardown budget bounds join/recovery;
the hosted gate still measures complete cleanup and fresh direct traffic inside
28 seconds of the fault. Normal requested shutdown retains the 20-second grace.
Linux adds `WatchdogSec=8s`, `WatchdogSignal=SIGKILL`, and `NotifyAccess=main`.
Only completed supervision iterations, including failed probe timeouts, feed it.
Watchdog/activation settings and host memory settings do not leak to the child.

Systemd 255 disables its watchdog outside START_POST, RUNNING and RELOAD states
in [`service_set_state`](https://github.com/systemd/systemd/blob/v255/src/core/service.c#L1145-L1146),
including STOP_SIGTERM. A manager-requested stop therefore uses our bounded
grace and the manager's stop timeout. A protocol-requested stop while systemd
still considers the host running continues the ordinary supervision loop;
completed stopping-state checks feed progress but do not count as forwarding.

The private Windows pipe uses `D:P(A;;GA;;;SY)` even when its nonce is known.
The kernel denies non-SYSTEM opens before the host-PID check. The nonce in argv
is a collision-avoidance name, not authentication or a secret capability; the
ProtectedPrefix namespace also prevents an unprivileged reader planting it.
The hosted `TestPrivatePipeACLBeforePIDCheck` discloses the exact name to a
Medium-integrity, Administrators-deny-only process and uses the host's actual
minimal access mask. No server Accept runs: ACCESS_DENIED proves the ACL alone,
before any PID check. Both Windows architectures require its PASS line.

## Outcomes and proofs

The child flushes a bounded completion record without waiting for a running
host. After exit, the host drains that pipe before classifying the raw result.
Only a matching unforced completion plus successful host cleanup can propagate
0 or 3. A raw job-close 0 is insufficient. Raw child code, forced/completed
flags, cleanup failures, dropped logs and successful forwarding-check count
remain in the instance outcome. Failed host cleanup changes a child 3 into host
failure 1 while retaining the raw child 3.

Host events carry timestamps taken at the call site, before asynchronous log
delivery: healthy forwarding, termination decision, joined exit and completed
cleanup. Each installed stall first requires an actual healthy forwarding
result. Data always fails the stall observation; a reset/EOF requires an
earlier termination event, while an OS timeout requires native socket evidence.
Failures continue through termination/cleanup measurement instead of letting
test cleanup destroy the evidence. The read-pump fault build records at most
eight outgoing TCP resets with direction and timestamps, without packet bodies.

The original Windows x64 failure on 889d90d6 was **not** proved to be a watchdog
reset: child 3392 became ready at 13:23:58.763 UTC and later exited with
`raw=0 forced=false completed=true` at 13:24:18.532 after test cleanup. There was
no termination decision for that instance. Its reset source remains unproved;
the strict assertion and new direction evidence stay in place. Four successful
forwarding checks were recorded in the preceding backpressure case. The two
zero-count exit-3 outcomes belonged to separate sub-second lifetimes.

Hosted regressions cover a 33-second start, a starting hang, a 15-second clean
stop, and routing restart inside the same child. An eight-stream, 60-second
echo load reports completed bytes, successful probes and failed probes. No
probe retries are introduced without those measurements.

### Findings from the 26cec04f hosted run

- Windows x64 and ARM64 both hit a registrar adoption lock cycle during the
  same-child restart fault. `testFault` held the protocol mutex while restart
  waited for an ACK; the private pump was waiting for that mutex in Supervision
  ahead of the ACK. A pure regression failed with the old locking and passes
  when the callback releases the protocol mutex while retaining mutation
  serialization. The registrar's three-second deadline is unchanged.
- Windows load completed 60 successful probes with zero failures on both
  architectures (7,474,348,032 bytes on x64). Linux's five-second failure was a
  fixture mismatch: binary data never completed its newline-based ping request.
  All eight reads timed out, then the test explicitly stopped a healthy child.
  The load now uses bounded ping/pong frames and requires 60 seconds of work.
- The zero-pass exit-3 outcomes on x64 were brief start/stop cases: child 6980
  lived from 14:01:05.059 to 14:01:05.450 UTC; child 4424 from 14:01:05.707 to
  14:01:06.106. The immediate check sees idle, and neither lives to the next
  one-second check. They briefly enter running, but no running-state forwarding
  probe completes; zero is expected, not a missing successful count.
- No pre-termination RST was reproduced in these jobs. The x64 read-pump flow
  proved OS exhaustion at 18.954 s. ARM64 observed WSAECONNABORTED at
  14:07:26.373 UTC after the host's 14:07:26.328 termination decision. The original
  889d90d6 reset remains unexplained; its strict check and direction evidence stay.
  ARM64's startup-hang case completed at 36.16 s, leaving 5.84 s against its
  unchanged 42 s test limit (35 s startup detection plus polling and cleanup).

The default lifecycle suite still selects `EngineService` without `m4_native`;
native unit watchdog settings are conditional on `Config.Native`. The host
starts its child idle, sends no routing start, and never manufactures intent
or sign-in. Only relayed authenticated Control requests start forwarding.

The Linux x64 lifecycle failure in job 120453669169 came from the old adapter's
port allocation: the failed API bind and the published proxy both used 38287.
Two independent allocate-and-close calls allowed immediate reuse. Both ports
are now held together during allocation, with a pure reuse regression and
explicit actual-port diagnostics. The frozen oracle's injected ports and all
frozen Node files remain unchanged.

The downstream sign-in message did not prove routing started: it tested
`status != off`, which also includes the logged error state. It edited the
boot journal with Control PID 7426 still alive; Start was a no-op, and the
next actual Control start was 14:00:19, after that assertion. Fault cases now
obtain fresh sessions and explicit healthy preconditions, retaining journals
and the crash-storm's accumulated state. Recovery overrides and unused fault
arms clean up even on failure. The reboot proof first stops both services,
preserves wanted=true, writes the previous-boot marker, and requires a new
Control PID, routing off and Engine stopped before sign-in. Windows x64,
Windows ARM64 and Linux ARM64 lifecycle jobs on 26cec04f passed; the new
independent reboot proof still requires hosted validation on this revision.
It observes off across five seconds of recovery ticks, not just one snapshot.
The separate 20.069 s forced-stop message is the acknowledged-stop barrier
case succeeding inside its existing 18–32 s assertion, not an unexpected kill.

### Same-child ownership retirement

ARM64 job 120468582339 on 29d6785f failed the second adapter preflight: two TUN
setup attempts but only one adapter creation, with no second interface/address
or firewall creation. The x64 job 120468582260 passed and recorded 24 health
passes. Wintun close and SetupAPI cleanup had completed, but the IP Helper
interface view still exposed the old adapter. The journal was retired too early.

Adapter removal now verifies absence in the same
[IP Helper interface table](https://learn.microsoft.com/en-us/windows/win32/api/netioapi/nf-netioapi-getiftable2ex)
used by creation, before allowing the journal's removed checkpoint. This is
option A: no ownership continuation or adoption exception. Polling is read-only,
bounded by the caller's deadline and five seconds, leaving room for registrar
retirement and journal completion within the 15-second service cleanup and
20-second host stopping bounds; a changed LUID is refused,
and timeout or inspection failure retains the ownership records. Existing
object refusals now name the object kind, and retirement has a separate timing.

The installed regression restarts twice without replacing the child. Each
cycle checks the same live-object baseline, new journal record IDs, real capture,
fresh traffic, and health for 23 seconds; final stop requires no leftovers.
Pure tests verify that delayed disappearance keeps journal records live and
that replacement/error/cancellation cannot silently retire ownership. Both
Windows hosted jobs require the retirement tests' PASS lines.

On 8e497723, x64 acceptance completed all 20 cycles, with confirmation taking
54.16–63.43 ms, then failed during final cleanup after the capacity workload.
ARM64 failed at the first cycle's stop. Both errors hit the added two-second
confirmation cutoff; those failures only establish a lower bound, not an
eventual removal time. That separate cutoff is removed: pending confirmation
continues within the existing stop budget and keeps ownership live. Shorter
caller deadlines, including supervisor recovery, still take precedence. A
regression keeps confirmation pending for 2.1 seconds and requires success;
cancellation and ownership-retention tests remain strict. Each completion now
logs architecture, elapsed time, poll count and outcome so hosted runs measure
the slow tail rather than censoring it at two seconds. Slow-tail completion
times on both architectures still require the new hosted run; 20 seconds is
the existing stop ceiling, not a newly measured removal bound. Cycle-stop
failures now include the native phase evidence; the 20-cycle gate is unchanged.

The later ARM64 rerun (job 120524427900) exhausted even that larger cap, so
the timer increase did not fix the underlying shutdown problem. Its captured
stack is a **10 ms phase snapshot**, not a deadline snapshot: `timings.begin`
arms it at 10 ms. It shows journal Cleanup overlapping Session.maintain waiting
on the registrar's process handle. `registrar.wait` waits for process exit,
not an IPC ACK: retire closes the control writer, waits two seconds for EOF
exit, then kills the verified registrar job and waits up to five seconds.
The registrar waits on control-pipe EOF and leaves device-handle cleanup to
process exit. The log contains no registrar-process stack and therefore cannot
prove where its kernel exit was blocked or that it remained blocked for 20 s.

Shutdown now joins the session before any journal mutation, removing the
overlap with WFP transactions and adapter removal. Windows Routes.Cleanup also
joins first for direct callers and refuses journal mutation if retirement
fails. Fingerprint-checked WFP deletions commit before adapter removal and
absence confirmation, rather than holding the BFE transaction across that wait;
the original journal intents remain until all cleanup succeeds. A pure
regression fails on the previous engine ordering and passes on
the new order. Ownership and absence checks are unchanged. Registrar retirement
now reports its elapsed time, observed process exit, escalation and exit code;
phase stack records report their actual age. Hosted proof of the ARM64 outcome
is still required; the missing registrar stack is not presented as a proved
kernel wait cycle.

Bootstrap readiness is again 15 seconds: it precedes routing startup and the
registrar's separate startup allowance. The 35-second bound applies only to
the routing `starting` state. The installed idle-error proof renews the lease
for 65 seconds, preserves the child PID, and then recovers routing in that child.
The x64 rerun (120524428050) also failed final cleanup after its capacity case.
Acceptance now explicitly stops with the independently reconciled TCP and UDP
cohorts still live, before fixture close. It requires acknowledgement inside
20 seconds, the existing strict stopped snapshot and fresh direct traffic.
All capacity/recovery assertions still run first; none are waived by this stop.

### Retirement failure and stop-cost audit

A failed stop is fatal, distinct from a cleanly idle configuration error.
`engine.go:122` routes start rollback through stopLocked; `engine.go:418` now
signals OnFatal when session join or journal cleanup fails. The notification
is the existing nonblocking service failure channel, not a new shutdown worker.

- **Control routing-off:** the protocol Stop returns failure, and the fatal
  signal wakes Windows `shutdown_windows.go:50` or Linux `service_linux.go:172`.
  The service exits with failure without depending on another Control request
  or on lease expiry. Previously a returned Stop error alone could leave it idle.
- **Service stop:** the service shutdown tail already calls runtime.Stop
  (Windows `shutdown_windows.go:97`, Linux `service_linux.go:182`). A retirement
  error remains a failed exit; it cannot become a clean routing-off outcome.
- **Start rollback:** stopLocked attempts cleanup and emits the same fatal
  signal if retirement/cleanup fails. A configuration error whose rollback
  succeeds remains idle and lease-renewable as specified.

Windows `routes_windows.go:395` still refuses journal mutations while session
retirement is uncertain. After the failed child exits and registrar ownership
ends, `native_supervisor.go:403` performs bounded journal recovery under the
released lifetime lock. Linux `routes_linux.go:939` attempts its journal cleanup
even when TUN close reported an error; the shared fatal signal also covers a
failed Linux cleanup. The injected installed proof exercises Control-driven
and manager-driven stop on both OSes, requires failure exit 1 without a forced
kill, real capture removal and fresh traffic inside 15 seconds. It starts with
verified live journal objects; Windows persistent WFP objects prove that
recovery, not adapter auto-removal alone, performed cleanup.

The existing close-start test is retained and rewritten to prohibit journal
mutation before session join, while preserving both close and cleanup errors.
A separate rollback regression requires the fatal signal. Product builds have
no retirement fault injector.

Timing baseline on main 504f9731: x64 job 120389519569 had 20 routingOffMs
samples, mean 101.74 ms, min 72.57 ms, max 131.60 ms. ARM64 job 120389519645
had mean 132.38 ms, min 92.48 ms, max 221.72 ms. Linux acceptance job
120389486146 completed all five start/traffic/stop cycles in 1.3 s; this is an
aggregate, not an isolated stop measurement. Linux lifecycle job 120382329800
reported clean-service-stop in 0.10 s. Historical final-quit duration and Linux
per-stop timings were not emitted. The harness now records those explicitly.
No post-reorder comparison is claimed: the old overlap unit test blocked
Windows acceptance on aadc43c1 and Linux acceptance was still running at audit.
New hosted timings and the unchanged 15 s stop/28 s hang gates must establish
the serialization cost; pure tests cannot supply those numbers.

### One terminal owner

The stop-failure escalation must not race a caller that already owns terminal
delivery. `StopWithReason` now passes an internal cleanup-owner context: the
engine returns all cleanup errors without also emitting OnFatal. Adapter loss
therefore retains its specific cause and receipt after cleanup attempts. The
Windows shutdown tail still exits with failure 1 when cleanup failed, keeping
the journal available for host recovery; only successful loss cleanup exits 3.

The same per-call ownership applies to service shutdown tails, the lease
cleanup reporter, and the generic pump-failure reporter. Each already returns
or reports the cleanup error to the service exit path. Ordinary Control Stop
and start rollback remain unowned and still emit fatal on cleanup failure.
The marker is neither wire-visible nor retained in engine state, so a later
ordinary failed stop cannot inherit suppression from a previous terminal call.

Before this fix's push, all 104 Windows-only test files in the affected engine,
platform, lifecycle, service, Wintun, winchild and lifecycle-test packages were
audited for stop/fatal/terminal/cleanup assertions. The adapter-loss and shutdown
contracts were read together, including competing explicit stop, lease retry,
late finalizer errors, blocked readers and retained journal ownership. The
existing Windows adapter-loss and shutdown-tail tests pass unchanged locally;
the fixed production-pipe and real-driver cases remain hosted-only. Both native
Windows jobs now require explicit PASS lines for the pure loss/tail contracts.
New shared tests cover lease-report ownership and the absence of suppression
leakage into ordinary stop. Existing fatal rollback tests remain in force.

### Reading atomically published outcomes

Native outcome/history readers now share the reader previously used only by
`lifecycle.Read`. `internal/sharedfile` opens Windows files with read/write/delete
sharing and retries only ERROR_SHARING_VIOLATION for at most two seconds.
Open errors remain unwrapped PathErrors, preserving `os.IsNotExist`. The outcome,
native-history and lifecycle limits remain 32 KiB, 16 KiB and 4 MiB respectively.
The audit found three native reader entry points: `host.ReadOutcome`,
`host.ReadRecord` (including reload after failed commits), and `host.Open`.
All now use the helper. Stand-in state reads already go through lifecycle.Read;
the native writer's AtomicWrite path does not read the destination itself.

No additional final-outcome signal is needed for classification. The host's
final write precedes nativeEngineService's return; the Windows service handler
returns its stopped result only after receiving that return. Product status
reads native outcomes only when the service is Stopped. The hosted assertion
already waits for Stopped and completed cleanup. SCM's configured failure
recovery command can subsequently republish pending/complete cleanup for the
same instance, preserving the child outcome. Thus a stopped host does not imply
an outcome file has no writer. Linux ExecStopPost is included in its manager's
stop boundary. Transient read failures must be handled by the sharing-safe
reader, not by sleeping or weakening the forced-failure assertion.

The Windows regression holds a publisher-style DELETE handle and proves plain
os.Open fails, while each native reader succeeds. It then races 128 actual
native replacements against all three readers and requires no failed reads or
classification changes. Publication uses the native rename/sync implementation
with ordinary temporary-directory ACLs so the pure test requires no SYSTEM
identity. Existing lifecycle publication and native commit-conflict tests remain.

The Linux acceptance `routes.default-route-removed` failure in job
120435827572 uses the namespace launcher's standalone `run` command, not the
service host or child command. Standalone has no HealthKey, so no private probe
endpoint or host watchdog runs. Route-loss handling, dial refusal and the test
are unchanged; the sole route snapshot change adds the TUN index. The Unix
listener refactor runs at startup, not during route refusal. A brief check of
12 main runs found 11 green and one unrelated capacity failure; the route case
passed in that failed run too. Latest main job 120389486146 passed the case with
a 2 ms slowest refusal. This establishes no prior reproduction of the 3111 ms
timing failure; it does establish that the new supervisor launch path is absent.

The installed service suite retains ACL denial, durable fencing, all totals
pages within ten seconds, policy/line/probe contracts and persistent cleanup
preconditions. It adds real host/child PID checks, real-host death with an
independently pinned child, Control-absent read-pump and whole-child stalls,
startup death, slow public/log readers, and clean child-3 propagation with failed
host cleanup. Crash/lease/hang bounds remain 12/42/28 seconds. The explicit
test-controller restart must restore fresh routing within 70 seconds; the
installed Control's own restart policy is proved in
[the production cutover](m4-production-cutover.md).

On Windows, suspending only the host leaves the runnable child's lease to
restore direct internet within 42 seconds. Suspending both while Control is
absent is the documented accepted gap: the test records capture still present
after 43 seconds, then resumes them and requires recovery within twelve seconds.
Linux's independent systemd watchdog must clean up both host-suspension cases
within 28 seconds. Held TCP survival is never required; OS give-up is recorded
only with socket evidence, and fresh-flow recovery remains mandatory.

CI requires named PASS lines for the installed cases and all launcher/registrar
proofs, including the normal and nightly full Wintun sequence. A skipped or
absent test fails. The breakaway guard scans the whole tracked Go tree except
test files and generated dependencies, including numeric mask spellings.

Local validation uses only pure tests and low-priority builds. Hosted timings,
OS behavior and resource costs remain measurements to collect on this PR's head.

References: [Go's Linux launch implementation](https://go.dev/src/syscall/exec_linux.go),
[Go's pidfd ownership](https://go.dev/src/os/pidfd_linux.go),
[parent-death semantics](https://man7.org/linux/man-pages/man2/PR_SET_PDEATHSIG.2const.html),
[systemd watchdog](https://www.freedesktop.org/software/systemd/man/255/systemd.service.html#WatchdogSec=),
[IP_UNICAST_IF](https://learn.microsoft.com/en-us/windows/win32/winsock/ipproto-ip-socket-options),
and [the reviewed Windows containment](m4-supervisor-containment.md).
