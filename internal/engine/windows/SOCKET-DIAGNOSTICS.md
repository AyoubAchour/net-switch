# Hosted socket handle diagnostics

These diagnostics collect evidence; they do not change or fix the socket backend.
Run them only on a disposable GitHub-hosted Windows runner. Never run this binary
on the live Net Switch PC. No adapter, route, firewall, service or Wintun fixture
is selected by the command below.

## One focused job

Use the project's pinned Go 1.27.2 toolchain (`$go` below). Both amd64 and arm64
are supported by the checked ABI layout. Keep the generation tripwire enabled.
The test binary checks `GITHUB_ACTIONS=true`,
`RUNNER_ENVIRONMENT=github-hosted`, and the explicit opt-in. Do not spoof those
values locally. No debugger installation or elevation is required by this code.

```powershell
$env:GOMAXPROCS = '2'
$env:NETSWITCH_SOCKET_DIAGNOSTICS = '1'
$env:NETSWITCH_EXPECT_HANDLECHECK = '1'
& $go test -c -p 2 -tags=netswitch_handlecheck -o "$env:RUNNER_TEMP/socket-diagnostics.exe" ./internal/engine/windows
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
& "$env:RUNNER_TEMP/socket-diagnostics.exe" '-test.v' '-test.count=1' '-test.failfast' '-test.timeout=10m' '-test.run=^(TestSocketHandleTrace(Control|Churn)|TestReadinessHalfClose(AndCancellation|AfterCollection)|TestReadyUDPDoesNotConsumeDatagrams)$'
exit $LASTEXITCODE
```

Keep the full console output and that exact executable as job artifacts. The
raw PC stacks plus module load addresses can be resolved later against matching
OS symbols and this executable; no symbol downloads occur in the diagnostic.
An optional race build uses the same command with `-race` on the build line,
with the runner's usual supported C compiler. It is a separate process/run, not
a retry of a failed assertion. Do not use `continue-on-error` or retry to green.

The opt-in suite must print `SOCKET TRACE CONTROL PASS`,
`SOCKET TABLE CONTROL PASS`, and `SOCKET TRANSFER CONTROL PASS`, and the selected
tests must actually run. Setup or control failure is fatal, not a skip/fallback
to the application's registry. Without opt-in, the two new tests skip and the
existing tests retain their ordinary assertions and behavior.

## What it captures

The first selected fixture enables process-local OS handle tracing **before its
first socket is created**. The control requires a real event OPEN and CLOSE,
plus a BADREF record with a nonzero stack and the correct process/thread IDs.
The invalid reference is a read-only `NtQueryObject` call on a sentinel. It
never closes a released handle or sets strict-handle mitigation. If the sentinel
unexpectedly exists, the control fails without modifying it.

`TestSocketHandleTraceChurn` has control, GoTCP and GoUDP variants. Each performs
32 transfers for each of TCP4/TCP6/UDP4/UDP6 (128 per variant, 384 total). The
churn variants allocate one fresh Go TCP listener or UDP socket after both Go
source descriptors close, keep it live during payload tests, and force GC.
This is bounded, deterministic allocation pressure, not unbounded parallel
load. The first failing round stops that test; `-test.failfast` stops the suite.

The staged fixture calls the existing duplication and readiness primitives in
the production order and records exact original, File and native identities.
It checks type/binding after File, native duplication, readiness registration,
each Go close, and churn/GC. Each family's first round verifies the live native
tuple/PID and actual newly recorded OS closes of all three descriptors. TCP
exercises reverse payload and FIN after peer EOF; UDP verifies 12,000 bytes and
both source addresses. This adds no socket duplication beyond the existing
transfer sequence.

The existing half-close and UDP datagram tests still call the real `Watch`.
Tracing brackets that call on one OS thread and saves its new OS records. The
private File value is **inferred only as a candidate** among same-thread
temporary opens; every candidate is printed, never asserted to be the File.
The new staged fixture supplies exact attribution without adding production
hooks. A live event marker checks that this short trace window did not wrap.

On the first failure, before socket/peer cleanup, logs include:

- The descriptor stage, original application/peer tuples, cached stage checks,
  OS histories of original/File/native numbers, and the real Watch window.
- Fresh `GetExtendedTcpTable` and `GetExtendedUdpTable` rows for both families,
  filtered by either original endpoint, including PID, TCP state and scopes.
  These are independent of the owner cache; an empty match and an API error
  are reported separately.
- Current native type, binding, peer and SO_ERROR; then one extra TCP write
  with a one-second peer read, or one UDP send to a separate loopback receiver
  with payload/source observation. Tables and traces are captured again after
  this probe. No diagnostic result rescues the original assertion.
- Final Close's actual return value and subsequent trace/table state. No raw
  I/O is attempted on a descriptor after our explicit final close.

## Mechanism and limits

The preferred documented viewer is Microsoft WinDbg/CDB `!htrace`. Neither was
installed in the implementation environment. This implementation needs no
debugger and instead uses **undocumented, test-only**
`NtSetInformationProcess/NtQueryInformationProcess(ProcessHandleTracing)` via
the already pinned x/sys wrappers. Unsupported OS behavior fails the control.
It is not a stable production API. The enable/query layouts were checked
against PHNT and ReactOS reference headers; amd64/arm64 offsets are asserted
and actual OS records are required as a runtime layout/control proof.

The history is a finite 16,384-entry ring. The API exposes no documented event
timestamp or ordering contract; output indices are not timestamps. Reused
values can have multiple generations in a query. Stage snapshots and multiset
differences help distinguish them, but cannot prove identity through a
check-to-syscall gap. Dumps cap a pathological per-handle history at 512 records
and explicitly report truncation. Missing entries/stacks, ring eviction or
unresolved kernel PCs cannot rule out a close. No `DuplicateHandle` or
`CompareObjectHandles` socket reference is created.

Tracing, thread pinning, queries and GC change timing. The trace controls prove
that this process captures its known operations; they do not prove that every
possible driver action is observable. Native tables and socket calls are
separate snapshots, not atomic. SO_ERROR may clear pending error state, so it
is read only after the first history/table capture. UDP Getpeername can normally
return ENOTCONN because the test socket is unconnected; it is not an anomaly.
The source/payload probe has a one-second receiver deadline, but a corrupted
handle now referring to an unrelated blocking socket could still stall the
sender; the focused process has a ten-minute outer timeout.

A live original tuple, successful extra payload, or absent FIN does **not**
disprove recycling: a leaked duplicate could keep the original connection
alive. Conversely a descriptor type change alone does not identify its closer.
No causal conclusion is drawn from the fact that the first recorded failures
came after duplication was introduced. A passing run is evidence of coverage,
not evidence that a root cause was fixed.

## References inspected

- [Microsoft !htrace](https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/-htrace)
- [Microsoft WSADuplicateSocket](https://learn.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-wsaduplicatesocketw)
- [Microsoft GetExtendedTcpTable](https://learn.microsoft.com/en-us/windows/win32/api/iphlpapi/nf-iphlpapi-getextendedtcptable)
- [Microsoft GetExtendedUdpTable](https://learn.microsoft.com/en-us/windows/win32/api/iphlpapi/nf-iphlpapi-getextendedudptable)
- [Microsoft SDK tcpmib.h](https://github.com/microsoft/win32metadata/blob/main/generation/WinSDK/RecompiledIdlHeaders/shared/tcpmib.h) and [udpmib.h](https://github.com/microsoft/win32metadata/blob/main/generation/WinSDK/RecompiledIdlHeaders/shared/udpmib.h)
- [PHNT ntpsapi.h](https://github.com/winsiderss/phnt/blob/master/ntpsapi.h) and [ReactOS pstypes.h](https://github.com/reactos/reactos/blob/master/sdk/include/ndk/pstypes.h), inspected 2026-10-21; ABI reference only, no implementation copied.
- Pinned Go 1.27.2 `net/file_windows.go`, `net/fd_windows.go`, and x/sys v0.49.0 Windows wrappers in this checkout. Go uses Winsock duplication and IOCP disassociation; these diagnostics do not substitute a handle-copy API.
