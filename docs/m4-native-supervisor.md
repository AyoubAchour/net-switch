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
after 250 ms closes that peer; replies and accounting are never silently dropped.
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

The host uses M2's three-second probe and approximately twenty-second continuous
failure window. Healthy forwarding resets the window. Off means no forwarding
is requested; a responsive status/renewal never proves active forwarding health.
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

## Outcomes and proofs

The child flushes a bounded completion record without waiting for a running
host. After exit, the host drains that pipe before classifying the raw result.
Only a matching unforced completion plus successful host cleanup can propagate
0 or 3. A raw job-close 0 is insufficient. Raw child code, forced/completed
flags, cleanup failures, dropped logs and successful forwarding-check count
remain in the instance outcome. Failed host cleanup changes a child 3 into host
failure 1 while retaining the raw child 3.

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
