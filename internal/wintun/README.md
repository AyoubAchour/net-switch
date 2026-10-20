# Windows packet sessions

This package uses the unmodified, hash-pinned Wintun 0.14.1 DLL only for adapter
management. `Create` owns an adapter; `Open` borrows one after checking its GUID.
The engine configures addresses, interface MTUs and routes separately. TestISP
can use the same package with a different name and GUID.

`StartSession` registers two rings in one VirtualAlloc region with the driver. Each ring
has a 12-byte header, a power-of-two capacity (128 KiB–64 MiB), and 65536 bytes
of wrap space. A packet has a four-byte length and four-byte alignment. Go's
sequentially consistent atomics cover publication and consumption on x64 and
ARM64. The native registration structures use the platform's pointer alignment.

Writes never wait for ring space, another writer or recovery. They copy a batch,
publish its tail, and signal the auto-reset receive event **unconditionally**.
There is one signal per nonempty accepted batch. This avoids the 0.14.1 receive
wake-up race without changing the signed driver. The driver's send side already
signals unconditionally; there is no send-side Alertable handshake in this ABI.

One ordered reader copies packets before releasing their space. Entry cursors,
alignment, lengths and available bytes are checked before any slice is formed.
Sized, all-zero placeholders from the driver's low-memory path are dropped and
counted. Packets larger than the caller's buffer are dropped and counted too,
so neither blocks later traffic. IPv4 fragments still require a valid IP header
checksum. Corruption wakes a maintenance goroutine that replaces the rings on
the same adapter. Repeated faults back off from 10 to 250 ms; a transient
registration-lock conflict retries with bounded backoff. Recovery failures are
terminal. Adapter removal returns `ErrAdapterRemoved`, logs once and does not
count as failed recovery. Events are bounded hints; counters are authoritative.

Close wakes readers, waits for the kernel to unregister its memory descriptors,
then releases events and native memory. Closing the owning adapter also calls
the DLL's adapter removal. PnP removal makes the 0.14.1 driver close the device
handle itself before writing Receive.Head and then Send.Tail. Write-side
disconnection waits up to 250 ms for that final marker and never closes an
ambiguous handle number. Every close attempt consumes our ownership, even on
failure. Registered memory is freed only after Send.Tail becomes MAXULONG;
otherwise it remains allocated until process exit, without a Go Pinner finalizer.
Process death makes the driver unregister its rings;
the service manager calls `RecoverAfterCrash` with the journaled name and GUID
under its ownership lock, as in system design section 2. Hosted tests confirmed
that process death alone leaves a phantom node: the cleanup hook removes only
the non-present Wintun device with the journaled GUID through SetupAPI. It does
nothing on a clean system and refuses a present adapter. It never loads the DLL,
so its asynchronous orphan sweeper cannot do this hook's work. `DeleteDriver` is an explicit installer operation only;
ordinary cleanup never removes a shared driver.

The DLL is loaded from beside the executable, verified before loading and
held open without write/delete sharing. Dependencies load from System32 only.
Only successful loads are cached; a failed load can be retried. It stays loaded
because its adapter API queues asynchronous cleanup callbacks.

The engine drains output packets already queued into batches of up to 64, with
no wait to fill a batch. It also passes verified TCP/UDP checksum metadata to
gVisor, retaining stack checks for fragments and unverified protocols.

## References, not incorporated source

The implementation was written for Net Switch from these ABI and lifecycle
contracts. No Wintun or wireguard-go source was copied or adapted.

- [0.14.1 driver ABI](https://git.zx2c4.com/wintun/tree/driver/wintun.c?h=0.14.1)
- [0.14.1 session API](https://git.zx2c4.com/wintun/tree/api/session.c?h=0.14.1)
- [0.14.1 adapter API](https://git.zx2c4.com/wintun/tree/api/adapter.c?h=0.14.1)
- [Missed wake-up fix ec0a6b98](https://git.zx2c4.com/wintun/commit/?id=ec0a6b98456fe1ba52567bb2add4bbf5f64315a1)
- [CM_Get_Device_Interface_List](https://learn.microsoft.com/en-us/windows/win32/api/cfgmgr32/nf-cfgmgr32-cm_get_device_interface_listw)

The existing distribution already includes the prebuilt binary license. Adding
this package does not incorporate or relicense the GPL driver/API sources.

## Hosted tests

All adapter tests require both the explicit test opt-in and a GitHub-hosted
runner. They never run in ordinary `go test`. x64 also runs real recovery and
lifetime tests under the race detector; ARM64 has no Go race detector.

The long test sends 200,000 UDP requests per implementation, one at a time, with
quiet periods from 0–200 microseconds spanning the driver's spin-to-sleep
boundary. QueryPerformanceCounter measures each round trip. A 250 ms timeout is
recorded, then one retry releases the DLL's queued packet; the slow attempt stays
in the distribution. Our path must have zero missed-wake rescues, without
exceptions. Every round trip over 50 ms is classified after the run. A 1 ms
QPC heartbeat on a locked OS thread uses a native high-resolution timer; an
independent Go timer sampler detects pauses across the process. Only shared
pause coverage leaving at most five sampling periods (5 ms) unexplained, without
a rescue, counts as an environment pause. A delayed sampler alone or more than
5 ms unexplained still fails our session. Coverage is the union of the intersections of
both samplers' gaps, clipped to the reply: multiple pauses count, but overlapping
or split observations cannot count the same time twice. This identifies process/host scheduling pauses,
not whether the Go runtime, OS or hypervisor caused them; the old uninstrumented
failure cannot be classified retroactively.

Every slow reply logs both sets of overlapping QPC intervals, our session's
read waits/wakes, write wakeups and atomic ring head/tail observations at the
gap endpoints and reply. The native sampler also retains observations during
in-flight replies older than 25 ms, so unexplained stalls have evidence from
inside the delay. Observations never block on a session lock. A hosted
test suspends only its own child process to prove both samplers detect a real
process pause, and verifies that an idle caller alone is not exempted.

Throughput uses delivered UDP bytes over a fixed interval and complete, hashed
TCP transfers, with one and eight streams. The UDP load generator is a separate
process, so it does not compete with only the Go session for Go scheduler slots
while the DLL executes outside that limit. Six pairs alternate implementation
order. Each TCP stack first runs two fixed, logged warm-up transfers: CPU profiles
show both implementations' initial connections warming from roughly 320–450 to
540–600 MB/s on the same x64 runner. The measured pairs compare the steady
state of a long-lived engine. All measured samples remain in the comparison:
a DLL `ERROR_INVALID_DATA` is logged
as a baseline failure, its partial UDP goodput (or zero for an incomplete TCP
transfer) is retained, and a fresh DLL session is used only for the next metric.
No failed sample is retried into a pass. The locked design's 10% performance
regression gate applies to the median of all six samples per implementation,
never to an individual pair. UDP packets per wake-up and isolated batch copy,
publication and SetEvent cost (1, 8 and 64 packets) are reported separately.
Packet corruption in delivered data,
unknown reference errors and failures of our session fail CI.
The median averages the two central samples, retains the raw trial order in
the report, and prevents one noisy trial from dominating either side. A
sustained regression still fails the same 10% gate.

TCP failures report session counters and ring cursors before socket or stack
teardown, along with transferred byte counts and one goroutine snapshot.
Both comparison paths use the engine's TCP stack: a TCP timeout is not evidence
of a DLL missed wake. A deterministic stack test loses an entire TCP window and
requires ACK-driven recovery after one timeout, including a new SACK during
recovery. No TCP deadline or session gate is relaxed for the DLL comparison.

Parallel senders verify every test payload. Deterministic malformed-entry tests
independently prove recovery, even if the driver corruption does not occur in a
particular stress sample. Lifetime tests count process handles and their kernel
object types after warming Go's OS-thread cache (six handles per Windows thread),
measure private memory after GC/scavenging, and enumerate PnP
records without filtering out non-present devices. A separate recovery test
measures these across 32 injected recoveries after eight warm-ups. Both tests
warm the runtime thread cache before measuring handles; recovery reports also
include thread counts and kernel object types when an assertion fails. The
recovery leak fault uses the reader-owned Send.Head, so driver discovery traffic
cannot overwrite it before detection. Removal runs
with a busy reader and writer; close-failure tests force GC with retained memory.
Crash cleanup runs in a fresh process, asserts the phantom existed, and removes
it without loading the DLL.

- [Windows high-resolution timing](https://learn.microsoft.com/en-us/windows/win32/sysinfo/acquiring-high-resolution-time-stamps)
- [Process handle snapshot ABI reference](https://github.com/winsiderss/phnt/blob/master/ntpsapi.h)
