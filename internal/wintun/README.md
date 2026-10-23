# Windows packet sessions

This package uses the unmodified, hash-pinned Wintun 0.14.1 DLL only for adapter
management. `Create` owns an adapter; `Open` borrows one after checking its GUID.
The engine configures addresses, interface MTUs and routes separately. TestISP
can use the same package with a different name and GUID.

`StartSession` registers two rings in one unnamed, pagefile-backed section. Each ring
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

## Registration owner

During removal the 0.14.1 driver itself closes the registering handle to its
device, by numeric value in the holding process, before writing
Receive.Head and then Send.Tail. A process that also opens and closes other
handles cannot prove which object such a value names at that moment. A forced
hosted reproduction showed the former in-process close destroying another
owner's object that had received the same number; that ordering now survives
only as a test-only negative control and comparison baseline.

So the engine never holds a device handle. `StartSession` starts a **registrar**:
the same executable in the hidden `RegistrarMode`, created suspended, assigned
to its own unnamed kill-on-close job, then resumed. Exactly five handles are
inherited through an explicit list: the control pipe (stdin), the reply pipe
(stdout/stderr), the section and the two ring events. No kernel object is
named. The engine passes the device interface path it already verified against
the adapter GUID, so the registrar loads no SetupAPI. The registrar refuses to
run unless both standard handles are pipes, the configuration matches, the path
is a Wintun interface, and the inherited handles are a `Section` and two
`Event`s. It maps its own view, opens the device once, registers that view and
replies with its PID and footprint. It then waits for the control pipe's EOF.
It never closes, reuses or touches the device value: process teardown owns it.

It is created in its own unnamed kill-on-close job **atomically at
CreateProcess** (the `PROC_THREAD_ATTRIBUTE_JOB_LIST` attribute), while still
suspended, before it runs any instruction. So even a parent crash in the old
create-then-assign window cannot orphan it: only the engine holds the job
handle, and closing it (or the engine dying) kills the registrar, suspended or
running. A registrar that ends for any reason wakes a parked reader through its
process handle. Every engine program that starts sessions dispatches
`RegistrarMode` first: the engine, TestISP and this package's tests.
The registrar runs with `GOMAXPROCS=1`, `GOGC=50` and `GOMEMLIMIT=8MiB`.
`Stats.Registrar` reports its start time, private bytes, heap, stacks and
handles, with `FootprintMeasured` false when the registrar could not read its
own counters (never a fabricated zero).

Close wakes readers, closes the control pipe and waits up to 2 s for the
registrar to exit (then terminates its job and waits up to 5 s). The engine and
the registrar hold **separate** mapped references to the same section, and the
driver only ever locked the registrar's reference. Once the registrar process
has exited, that reference is gone, so the engine always unmaps its own view
and closes its section handle unconditionally — it never needs to retain memory
and does not wait for the ring markers to protect its own view. The markers
(Receive.Head then Send.Tail) are awaited only as a logged confirmation that
the driver released the registration; a missing marker is reported, not fatal
to the engine's teardown. Every value the engine closes is one it alone owns,
and every close attempt consumes that ownership even on failure. Closing the
owning adapter also calls the DLL's adapter removal.

A lost registration — real adapter removal **or** the registrar exiting on its
own — stops the session with `ErrAdapterRemoved` and never triggers an
automatic rebuild. A confirmed owner loss takes precedence even over a queued
ring-corruption cause, so a dead owner is never rebuilt in place. Maintenance
also samples the driver's loss markers **before** stopping the registrar:
either marker already present prevents reopening even if the helper then exits
zero. Markers first published by our own stop do not prevent corruption recovery.
Receive.Head alone can also mean the driver rejected a damaged receive ring;
it remains a session loss, matching the existing writer's disconnected result.
Owner death
is classified from the registrar's **completed** exit during teardown, not a
pre-close sample: it is owner death if the process was already gone before our
stop, or ended non-zero without our own escalation; a clean EOF stop exits
zero. That exit is then joined with `ErrRegistrarExited`, while real removal
carries `ErrAdapterRemoved` alone. The distinction is a diagnostic — both are
adapter-lost — and is best-effort, not a hard guarantee under every race.
On a disconnected write, a zero-time process wait adds `ErrRegistrarExited` if
the owner is already signalled. If its markers precede that signal, the first
write reports only `ErrAdapterRemoved`; reads and later writes use maintenance's
completed-exit classification. Healthy writes gain no native process poll.
Reporting the distinct "adapter lost" reason to the controller, and any restart
budget, belong to the engine/controller, not this package. Only ring
**corruption** reopens the rings (and thereby starts a fresh registrar).
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
independent Go timer sampler detects pauses across the process. Both timestamp
their observations with QPC. A gap longer than two sampling periods (2 ms)
means a sample was missed; ordinary 1 ms intervals do not count as pauses.
The gap retention cutoff is separate from the classification allowance. Only shared
pause coverage leaving at most five sampling periods (5 ms) unexplained, without
a rescue, counts as an environment pause. A delayed sampler alone or more than
5 ms unexplained still fails our session. Coverage is the union of the intersections of
both samplers' gaps, clipped to the reply: multiple pauses count, but overlapping
or split observations cannot count the same time twice. This identifies process/host scheduling pauses,
not whether the Go runtime, OS or hypervisor caused them; the old uninstrumented
failure cannot be classified retroactively.

Every slow reply logs both sets of overlapping QPC intervals, every sampler
timestamp inside and bracketing the reply, the unexplained duration, our session's
read waits/wakes, write wakeups and atomic ring head/tail observations at the
gap endpoints and reply. The native sampler also retains observations during
in-flight replies older than 25 ms, so unexplained stalls have evidence from
inside the delay. Observations never block on a session lock. A hosted
test suspends only its own child process to prove both samplers detect a real
process pause, and verifies that an idle caller alone is not exempted. Another
hosted test holds the real session's reader lock, proves a packet is queued
behind it, then releases it after 80 ms while both samplers continue running.
That completed reply must still classify as a session stall.

### ARM64 borderline trace

[Job 118761509687](https://github.com/AyoubAchour/net-switch/actions/runs/39461404208/job/118761509687)
recorded sequence 174468 at QPC frequency 10 MHz:
the trip was `[3786091692, 3786734914]`, the heartbeat gap was
`[3786075803, 3786730140]`, and the two scheduler gaps were
`[3786075928, 3786320714]` and `[3786366941, 3786733534]`.
Their intersections explain 59.2221 ms of 64.3222 ms. The remaining 5.1001 ms
consists of a 4.6227 ms hole between scheduler gaps and 0.4774 ms after the
heartbeat resumed. Adding the two scheduler durations directly would ignore
clipping to the trip and the heartbeat.

The old monitor discarded every interval of 5 ms or less. It therefore cannot
tell us whether that hole contained one late sample or several ordinary samples.
Both histories produce the same old log. The regression replays both possible
histories: a recorded 4.6227 ms missed sample explains 63.8448 ms and classifies as
an environment pause; four ordinary samples leave 5.1001 ms unexplained and
still classify as a session stall. With only the original evidence, the
classification stays `session_stall`. Nearby gaps are never joined across
unobserved time.

This is a demonstrated measurement blind spot, not proof that the historical
trip had no session delay. At the last heartbeat, the send ring still held one
96-byte entry and one read wait had not returned; at reply that entry was read
and its echo written. No rescue, drop, corruption or recovery was recorded.
These snapshots cannot distinguish a descheduled reader from a delayed wake.
No production session code changes on that evidence.

The pinned Go 1.27.2 ARM64 runtime's `nanotime1` and `time.now` read Windows'
shared interrupt/system time; `time.Sleep` uses that clock to schedule the Go
sampler. Socket deadlines also use Go time. Neither provides the timestamps for
the trip, samples or intersections: those already use QPC throughout. Changing
the timestamp clock would therefore not repair this trace.

### Performance and lifetime

Throughput uses delivered UDP bytes over a fixed interval and complete, hashed
TCP transfers, with one and eight streams. The UDP load generator is a separate
process, so it does not compete with only the Go session for Go scheduler slots
while the DLL executes outside that limit. Twelve matched pairs alternate
implementation order, starting with ours. Within each pair, each metric runs
back to back through the two sessions on the same adapter before proceeding to
the next metric. Each TCP stack first runs two fixed, logged warm-up transfers: CPU profiles
show both implementations' initial connections warming from roughly 320–450 to
540–600 MB/s on the same x64 runner. The measured pairs compare the steady
state of a long-lived engine. All measured samples and errors are reported:
a failed DLL measurement also fails the comparison instead of supplying a
favorable denominator. No failed sample is retried into a pass.
The 10% regression gate applies to the median of the twelve **per-pair**
ours/DLL ratios, not the ratio of separately pooled medians. Throughput must
reach 0.90; latency must stay at or below 1.10. This design decision controls
for changing runner conditions without changing the regression allowance.
Both implementations report read packets per successful native read wake-up
and written packets per accepted nonempty write batch for every sample.
The DLL hides its conditional write-event signals, so its batch count is
explicitly not a signal count. Our actual write signals are reported too.
Isolated batch copy, publication and SetEvent cost (1, 8 and 64 packets) are
reported separately.
Packet corruption in delivered data,
unknown reference errors and failures of our session fail CI.
The median averages the two central ratios and retains raw pair order and
all sample values in the report. A
sustained regression still fails the same 10% gate.

TCP failures report session counters and ring cursors before socket or stack
teardown, along with transferred byte counts and one goroutine snapshot.
Both comparison paths use the engine's TCP stack: a TCP timeout is not evidence
of a DLL missed wake. A deterministic stack test loses an entire TCP window and
requires ACK-driven recovery after one timeout, including a new SACK and a
real reordering-timer expiry during recovery. In the
[round-2 mutation proof](https://github.com/AyoubAchour/net-switch/actions/runs/39439354881/job/118684802958),
the fixed stack passed all four cases 25 times each; removing each of the
three guards independently failed its targeted case all ten times. The SACK
control passed in every mutation. The temporary switches were removed after
this proof. No TCP deadline or session gate is relaxed for the DLL comparison.

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

Registrar tests: `TestRingRemovalBetweenMarkerCheckAndClose` keeps the legacy
ordering as a negative control (it must destroy the witnessed replacement, or
the handlecheck tripwire must stop it) and applies the same injection to the
production teardown with a device-less fixture registrar, which must close
only its own objects. `TestRegistrarRefusesWithoutInheritedCapabilities` needs
no adapter. Hosted: `TestWintunRegistrarSession` (8 MiB rings; no non-pipe file
handle added to the engine, including the DLL's adapter creation),
`TestWintunRegistrarLoss` (registrar termination, job termination,
query-remove, creator death; a parked reader with no write traffic must wake and
32 unrelated engine events must survive) and `TestWintunRegistrarEngineCrash`.
`NETSWITCH_WINTUN_REFERENCE=inprocess` runs the unchanged performance gate
against the test-only in-process registration.

### TCP integrity investigation (hosted CI only)

Ordinary TCP performance runs also compare each existing 32 KiB receive read
against the shared deterministic sender slice using `bytes.Equal`. They retain
only the first difference, with stream/transfer ID, implementation, pair,
warm-up/measurement label, received length, byte offset and up to 64 bytes
before and after it (clipped to that read). Reading and SHA-256 continue
unchanged. `tcp_payload_difference` emits the excerpt and both hashes before
teardown, including partial reads. No 512 MiB receive body is retained.
The expected slice is shared with the sender; SHA-256 remains the independent
check if that slice itself changes. The opt-in diagnostic uses separate oracles.

The small proof first runs `TestWintunCaptureProof` in an **ordinary untagged
binary**: eight fixed alternating-order SHA-only/capture pairs per implementation,
same shared payload and two warm-ups. It logs every matched rate and ratio;
the per-mode median must retain 95% of SHA-only throughput. This is an overhead
guard, not a claim that the overhead has already been measured negligible.
The only capture bypass is a fixture field set by this hosted proof's baseline;
normal CI has no environment switch that can silently disable the comparison.

`wintun-nightly.yml` runs at 03:17 UTC once merged into the default branch.
Eighteen shards per architecture/scenario, two cycles each, produce 72 jobs
under one `max-parallel: 10` cap. Each boundary gets three shards per variant.
Observed job durations predict roughly 2.5–3 hours with available runner slots;
queue contention can extend this. The nightly workflow also allows manual
dispatch and serializes its own invocations. Do not launch an additional manual
hunt alongside it if the combined work would occupy the remaining CI slots.

The job summary distinguishes positive TCP byte/hash evidence, incomplete
diagnostics, timeouts and unrelated test failures. Known recovery/throughput
failure signatures are named separately. All failed exit codes remain failed;
no general test failure is silently waived or labelled TCP corruption. Detailed
boundary records stay in the Actions log. This workflow reports observations;
it never closes the release blocker.

First dispatch `ci.yml` with `wintun_integrity=true`,
`wintun_integrity_arch=both`, `wintun_integrity_shards=2`, and
`wintun_integrity_scenario=proof`: **four jobs total**. Both architectures share
one matrix with `max-parallel: 10`; it is not a separate cap per architecture.
The defaults select a two-shard proof. Do not widen exposure until it passes.
Only diagnostic jobs run unless `regular_jobs` is explicitly set.
It builds with `-tags=wintun_integrity` and opts in at runtime with
`NETSWITCH_WINTUN_INTEGRITY=1`. Normal binaries compile out the ring observers;
normal performance runs keep the original payload, warm-ups and gate.

The proof measures each of six boundary choices on both implementations using
three fixed matched clean/instrumented pairs, alternating which runs first.
Clean means the original workload in the same binary with observers disabled.
Every configuration must retain at least 80% of clean throughput (median of
the three ratios). Failed/incomplete samples stay in place and prevent a ratio;
there are no retries. Wall time and heap allocation/reservation are also logged.
Precomputing independent payload oracles happens before the transfer timer,
and adds up to 512 MiB for eight streams in addition to sender buffers. Thus a
passing transfer-throughput check is not a claim of identical setup/memory cost.

After qualification, `isolated` and `full` scenarios support `1`, `2`, `5`,
`10` or `20` shards per selected architecture. Select `hunt` to put **both
scenarios in the same matrix** with the same shared ten-job cap; do not launch
two separate ten-concurrency dispatches. Matrix order interleaves architectures
and scenarios for each shard so every kind starts in the first wave.
`wintun_integrity_boundary` selects
`receive` (default), `ingress`, `echo`, `output`, `send`, or `host`. Host SHA-256
and first-difference checks always remain enabled. The explicitly expensive
`all` option is for follow-up localization, not a qualified low-overhead mode.
`rotate` assigns the six qualified single-boundary choices by shard, repeating
receive/ingress/echo/output/send/host. With 20 shards, receive and ingress each
get four jobs per architecture/scenario; each other boundary gets three.
The chosen boundary is fixed within a job and included in its exposure summary.
No individual sampled run claims to have checked its unselected boundaries;
do not combine different transfers into a single causal trace.

An isolated repeat runs all 12 positions of `tcp_8_MBps`: two serial 64 MiB
warm-ups, then eight 64 MiB streams, for both the signed DLL and our session,
alternating which mode runs first. A full repeat replays the normal Wintun
job: ring/recovery tests, registrar tests, ping-pong, the **entire five-metric
performance test**, its in-process-reference comparison, lifetime/crash,
both CPU profiles, fuzzing, and x64 race/handle checks. The manifest is checked
against the normal job's selectors and ordering. Its normal failure-dependent
steps remain failure-dependent; later `!cancelled()` phases still execute.

Each phase gets a fresh process, as in the original job. Each performance
pair shares one adapter across all metrics and modes; each fixture starts a
fresh session and stack. TCP warm-ups and measurement share that fixture's
stack. This restores UDP and single-stream TCP activity before eight-stream
TCP without inventing adapter reuse across unrelated tests. Kernel/host state
can carry across phases and repeats on the same runner; the runner adds no
driver reset or extra GC. The release registrar remains uninstrumented.

There is a 45-minute execution budget inside each 60-minute job. A new repeat
starts only with room for a complete case; native process-tree deadlines also
bound builds/tools. A case that overruns fails explicitly as incomplete. The
full performance timeout is 20 minutes for diagnostic overhead; the original
per-transfer deadlines, sizes and warm-up counts stay unchanged. Profile
phases use their original 24 transfers with payload diagnostics off.
`INTEGRITY_EXPOSURE` reports completed DLL and in-process TCP-eight pair counts
separately, plus measured TCP streams (excluding warm-ups and CPU profiles).
An unsuccessful cycle stops repetition; no sample or pair is retried, dropped
or replaced. Instrumented rates never enter the clean performance gate.

Opt-in lifecycle records identify process, phase, shard, repeat, test path,
adapter GUID and session. They record adapter creation/close and session
start, joined pumps and close. Our session stats include ring cursors,
registrar identity and recovery counters; the DLL exposes counters only.
These observations do not assert that unobservable kernel caches were reset.

The host registers each tested tuple and its independent oracle before sending
payload. Observed SYN/SYNACKs provide sequence bases; a SYNACK can recover a
missed SYN. If observation starts mid-flight, a unique 32-byte oracle match can
recover a sequence base without assuming the first offset is zero. Inferred
bases are labelled `payload_oracle`; unseen earlier traffic is not certified.
Late unbound SYN hints cannot evict bound transfers. Payload for an unregistered
tuple is counted separately: round 2 demonstrated late payload from a previous
fixture, rather than a missing SYN for a current transfer. A bound stream whose
sequence/coverage cannot be resolved is **diagnostic incomplete**, not a byte
integrity failure. Actual byte/hash mismatches take priority if both occur.

The diagnostic records each client tuple, server address and known ISNs.
SYN consumes one sequence number; modular offsets tolerate wrap,
retransmissions and reordering. The payload encodes a transfer/stream identity
and block offset over the original deterministic pattern. Warm-up identities
remain distinct. An unknown payload identity, ambiguous reused sequence range,
fragment or malformed TCP header invalidates the diagnostic rather than
pretending the unobserved boundary was clean. Empty late ACK/RST packets from
previous fixtures are counted separately.

The selected `WINTUN_RESULT` boundary is native receive/copy before release,
stack ingress after packet-buffer creation, echo reads, stack output, native
send/source before publication, or host reads. Clean data uses fast exact byte
equality against an immutable precomputed oracle; the sender gets separate
storage. The native copy equality check avoids rechecking identical payload
twice. Host equality runs without the global packet-tracking lock. Pattern
regeneration and IP/TCP checksum calculation happen only on mismatch; packet
records explicitly say whether their checksums were checked.
Each connection/stage retains only its first failure (offset and up to 16
expected/actual bytes), its preceding 64 packet records, and a rolling last 64.
There are at most 16 connection records per fixture. Successful connections
emit identities, byte/packet counts and host hashes; failed connections also
emit bounded history immediately on separate JSON lines, so a later timeout
cannot erase the first bad boundary. Byte counts include retransmits.
Native slices are never retained or accessed after release/publication.

Read the first-failure records in path order, comparing the same identity and
offset. Bad native receive narrows the issue to the host/driver/DLL receive
side. Good native receive but bad copy identifies the wrapper. Good ingress
with a bad echo read implicates receive/reassembly; a good echo read with bad
output implicates sending/queueing. Good reserved send bytes with a bad host
stream narrows it to the driver/host receive side. These observations alone do
not prove which closed-source component is at fault, and missing coverage must
not be called clean. A passing diagnostic does not clear the rare corruption.

Samples now carry status, nullable value, original error, pair, mode and metric.
All pair positions are reported. Any invalid sample yields an
`integrity-invalid comparison` with its original transfer error, and no ratio
is returned until every position is valid.

The boundary ordering was checked against the
[Wintun API contract](https://git.zx2c4.com/wintun/tree/api/wintun.h) and
[session implementation](https://git.zx2c4.com/wintun/tree/api/session.c), and
the vendored gVisor/gonet and local Link ownership paths. No upstream source
was copied into this diagnostic.

- [Windows high-resolution timing](https://learn.microsoft.com/en-us/windows/win32/sysinfo/acquiring-high-resolution-time-stamps)
- [Process handle snapshot ABI reference](https://github.com/winsiderss/phnt/blob/master/ntpsapi.h)
