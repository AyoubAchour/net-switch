# M4 supervisor: containment prerequisites

This is the first sequential PR for option (e), recorded in spec §3.4. The full
hosting, relay, health and installed fault matrix would exceed the review-size
target. This part establishes Windows launch and registrar ownership first.
The installed native service still runs in process until the next PR.

## Launch and ownership

`winchild.StartSelf` creates only the caller's own executable. It pins the image
against replacement during creation, uses `PROC_THREAD_ATTRIBUTE_JOB_LIST`, and
keeps the primary thread suspended until the caller explicitly resumes it.
The returned process handle supplies the image path and creation FILETIME and
is used for every wait and termination. A PID is diagnostic metadata, never the
authority for killing a replacement process. The caller must close every result.

The job is unnamed, has kill-on-close and a one-process limit, and is held only
by the supervisor. Exactly three pipe handles are inherited. The child does not
inherit the job handle and cannot keep the guard alive after the supervisor dies.
Arguments and the explicit Unicode environment are bounded. No fallback creates
an unassigned process. Setup, resume and close errors remain errors; the native
exit code and whether termination was forced remain separately available.

## Registrar placement

The native child can opt into **explicit** breakaway only after verifying its
immediate job's kill-on-close, one-process and breakaway limits. Silent breakaway
is refused. This bootstrap function is not enabled by an environment variable
or a standalone runtime command.

The registrar then requests breakaway and its own existing job assignment in one
CreateProcess call. Its eight UI restrictions, one-process limit, explicit
five-handle inheritance and kill-on-close behavior remain intact. The child owns
that registrar job: host death kills the child, whose handle teardown kills the
registrar, including either process dying before its child resumes.

Breakaway permission is a job policy, not an executable allowlist or a security
sandbox for compromised SYSTEM code. Our launch sites still select their own
verified image; only the registrar requests breakaway. An incompatible ancestor
job fails creation rather than weakening UI restrictions. No extra installed
service or host-brokered registrar protocol is introduced.

## Hosted evidence

| Case | Required evidence |
| --- | --- |
| Suspended launch | Actual job membership before resume; an exit-only child cannot finish before resume |
| Create-return death window | A negative control leaves a suspended child alive when its creator dies before assignment; the atomic launcher reaps it at the identical boundary, before identity checks |
| Startup exits | Raw 0, 3, 7 and exception-shaped codes retained; forced suspended termination stays forced |
| Close error | A real close followed by an injected error is returned without rewriting raw exit 3 |
| Unread output | Both output pipes contain independently observed data; termination completes without either reader |
| Host dies before child resume | Independently pinned child exits through the lifetime job |
| Host or child dies before registrar resume | Registrar is alive before the fault, outside the outer job, with all UI restrictions; then exits |
| Host or child dies after registration | Real packets succeed first; both child and registrar exit; a fresh session on the same surviving adapter carries packets |

The registrar proof launches the built, hashed production engine as the registrar,
not a simulated helper. Native-service jobs run these proofs on Windows x64 and
ARM64 with handle ownership instrumentation. Existing Windows and Linux installed
service checks still run. Local validation is limited to pure unit tests and
builds at Idle priority, with two cores; hosted results remain required.

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
