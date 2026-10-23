# M4 native supervisor

The `m4_native` service now hosts one verified native child. This implements
option (e), recorded in spec §3.4. Control cutover and restart/backoff/latch
policy remain in the later cutover PR. The host never respawns a child.

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
An error has 30 seconds for Control recovery or child exit. These lifecycle
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
test-controller restart must restore fresh routing within 70 seconds; production
Control restart policy itself still belongs to cutover.

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
