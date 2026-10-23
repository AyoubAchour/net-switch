# M4 supervisor: containment prerequisites

This is the first sequential PR for option (e), recorded in spec §3.4. The full
hosting, relay, health and installed fault matrix would exceed the review-size
target. This part establishes Windows launch and registrar ownership first.
The installed native service still runs in process until the next PR.

## Launch and ownership

`winchild.StartSelf` creates only the caller's own executable. Startup captures
the volume serial and file ID; both the pinned candidate and the created child
must match that ID, even after an update renames the old image aside. Paths are
diagnostic only, so aliases do not cause false mismatches. It pins the image
against replacement during creation, uses `PROC_THREAD_ATTRIBUTE_JOB_LIST`, and
keeps the primary thread suspended until the caller explicitly resumes it.
The returned process handle supplies the image path and creation FILETIME and
is used for every wait and termination. A PID is diagnostic metadata, never the
authority for killing a replacement process. The caller must close every result.

The job is unnamed, has kill-on-close and a one-process limit, and is held only
by the supervisor. Exactly three pipe handles are inherited. The child does not
inherit the job handle and cannot keep the guard alive after the supervisor dies.
Arguments and the explicit Unicode environment are bounded; empty/malformed
entries are rejected instead of silently ending the block. No fallback creates
an unassigned process. Setup, resume and close errors remain errors; the native
exit code and whether termination was forced remain separately available.

## Registrar placement

The native child can opt into **explicit** breakaway only after verifying its
immediate job's kill-on-close, one-process and breakaway limits. Silent breakaway
is refused. This bootstrap function is not enabled by an environment variable
or a standalone runtime command. The one-process limit rejects ordinary
descendants. The registrar is the sole reviewed breakaway exception in §3.4.

The registrar then requests breakaway and its own existing job assignment in one
CreateProcess call. Its eight UI restrictions, one-process limit, explicit
five-handle inheritance and kill-on-close behavior remain intact. The child owns
that registrar job: host death kills the child, whose handle teardown kills the
registrar, including either process dying before its child resumes.

Before resume, the child hands the host its registrar process capability and
waits for acknowledgement over the private channel. Production `TrackRegistrar`
duplicates from the verified child, checks the PID and retains SYNCHRONIZE only.
No job handle is copied. At most four pending/live observers remain; exited
generations are pruned. `Process.Wait` joins child and registrars, preventing a
healthy host from restarting while registration teardown is unfinished. A
registrar without acknowledgement never resumes.

After host death no observer survives. New registration retries only the
driver's unclaimed `ERROR_ALREADY_INITIALIZED` state, on the same device handle,
with at most 630 ms backoff. Success and other errors are never retried. The
containment test now starts its fresh session before its independent registrar
check, so a test-only wait cannot hide the production restart race.

Breakaway permission is a job policy, not an executable allowlist or a security
sandbox for compromised SYSTEM code. Our launch sites still select their own
verified image; only the registrar requests breakaway. An incompatible ancestor
job fails creation rather than weakening UI restrictions. No extra installed
service or host-brokered registrar protocol is introduced.

A source guard permits the breakaway creation flag only in that registrar path.
Product engine builds compile out netsh and the TCP configuration worker
launcher; acceptance/handle-trace builds retain them. Environment flags cannot
enable them in a product binary. Native counters, bounded logs and refusals
remain, with configuration diagnostics explicitly disabled. No documented
native enumeration equivalent to both dynamic and active excluded ranges was
found; partial data is not substituted for the test-only diagnostic.

The native-service matrix's **Windows process diagnostic build contracts** step
requires explicit PASS results for the product-off proof and both trace-build
proofs (live UDP netsh settings and the restricted TCP configuration worker), on
x64 and ARM64. Missing or skipped tests fail the step. Capacity/control fixtures
that need these readers reject a product build before allocating their sockets;
their acceptance and focused diagnostic workflows already use the trace tag.

## Hosted evidence

| Case | Required evidence |
| --- | --- |
| Suspended launch | Actual job membership before resume; an exit-only child cannot finish before resume |
| Handle inheritance | The suspended child's table has exactly three inherited pipes; an inheritable event is absent with HANDLE_LIST and present in the no-list negative control |
| Create-return death window | A negative control leaves a suspended child alive when its creator dies before assignment; the atomic launcher reaps it at the identical boundary, before identity checks |
| Startup exits | Raw 0, 3, 7 and exception-shaped codes retained; forced suspended termination stays forced |
| Close error | A real close followed by an injected error is returned without rewriting raw exit 3 |
| Natural-exit race | Exit 3 wins between the liveness poll and termination; the dedicated kill code keeps `Forced` false |
| Unread output | Both output pipes contain independently observed data; termination completes without either reader |
| Host dies before child resume | Independently pinned child exits through the lifetime job |
| Host or child dies before registrar resume | Registrar is alive before the fault, outside the outer job, with all UI restrictions; then exits |
| Host or child dies after registration | Real packets succeed first; both child and registrar exit; a fresh session on the same surviving adapter carries packets |

The registrar proof launches the built, hashed production engine as the registrar,
not a simulated helper. Native-service jobs run these proofs on Windows x64 and
ARM64 with handle ownership instrumentation. Existing Windows and Linux installed
service checks still run. Local validation is limited to pure unit tests and
builds at Idle priority, with two cores; hosted results remain required.
Hosted launcher tests fail, rather than skip, if their CI variable is missing;
the regular hosted Go jobs also set it explicitly.

## Job-close exit evidence

On `480f3aa6`, [ARM64 job 120305520806](https://github.com/AyoubAchour/net-switch/actions/runs/39920875671/job/120305520806)
and [x64 job 120305520603](https://github.com/AyoubAchour/net-switch/actions/runs/39920875671/job/120305520603)
both observed child exit 0 after killing the host. Every child was gone. The
test incorrectly treated that raw number as a clean completion. Windows
documents termination on last job-handle close without promising a nonzero exit
value. Explicit TerminateProcess/TerminateJobObject instead accept an exit value.

The corrected test still requires child death, registrar death, unchanged UI
limits and same-adapter recovery. Explicit child kills retain code 37. Host
kills record the raw child code and require the actual host outcome to be
failure, never 0 or 3. Raw child 0 is not routing-off evidence: hosting must
require authenticated terminal completion and successful host cleanup, and
manager-observed host death overrides the descendant's raw code. Host-requested
termination uses a dedicated code; `Forced` is true only when that code wins.

## Next sequential PR

After this prerequisite merges, branch again from main for the thin service host,
private native relay, child-owned lock/epoch/revision/lease, bounded private
forwarding checks, awake-time/resume handling and Linux WatchdogSec notifications.
The host never respawns. Control retains restart/backoff/latch policy.

That PR must prove the 28 s hang, 12 s crash, 42 s lease and 70 s recovery gates;
public IPC PID equals host and engine PID equals child; exact child-3 to manager
propagation with cleanup failure; Control-absent child stalls; host crash and
suspension; and the accepted simultaneous-host-and-child hang gap. None of those
watchdog/service claims is credited to these containment tests.

References: [atomic job assignment](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-updateprocthreadattribute),
[nested jobs and UI limits](https://learn.microsoft.com/en-us/windows/win32/procthread/nested-jobs),
[breakaway and suspended creation](https://learn.microsoft.com/en-us/windows/win32/procthread/process-creation-flags),
[immediate-job queries](https://learn.microsoft.com/en-us/windows/win32/api/jobapi2/nf-jobapi2-queryinformationjobobject).
Further references: [job-handle closure](https://learn.microsoft.com/en-us/windows/win32/procthread/job-objects),
[explicit job exit values](https://learn.microsoft.com/en-us/windows/win32/api/jobapi2/nf-jobapi2-terminatejobobject),
[file IDs](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-getfileinformationbyhandleex),
[Wintun registration ownership](https://github.com/WireGuard/wintun/blob/0.14.1/driver/wintun.c),
and [documented port-range inspection](https://learn.microsoft.com/troubleshoot/windows-client/networking/tcp-ip-port-exhaustion-troubleshooting).
[LookupPersistentUdpPortReservation](https://learn.microsoft.com/en-us/windows/win32/api/iphlpapi/nf-iphlpapi-lookuppersistentudpportreservation) takes an already known range and returns
its token; [GetUdpTable](https://learn.microsoft.com/en-us/windows/win32/api/iphlpapi/nf-iphlpapi-getudptable) lists endpoints. Neither is a replacement for the full
dynamic-range and active-exclusion census.
