# Windows packet sessions

This package uses the unmodified, hash-pinned Wintun 0.14.1 DLL only for adapter
management. `Create` owns an adapter; `Open` borrows one after checking its GUID.
The engine configures addresses, interface MTUs and routes separately. TestISP
can use the same package with a different name and GUID.

`StartSession` registers two pinned Go byte arrays with the driver. Each array
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
Corruption or driver disconnection stops that generation and wakes a maintenance
goroutine. It unregisters the old rings before releasing memory and handles,
then registers fresh rings on the same adapter. Failed recovery is terminal and
visible to callers. Counters retain every corruption; logs are limited to one
per ten seconds, with recovery failures always logged. Events are bounded hints.

Close wakes readers, waits for the kernel to unregister its memory descriptors,
then releases events and unpins memory. Closing the owning adapter also calls
the DLL's adapter removal. PnP removal makes the 0.14.1 driver close the device
handle itself; its terminal ring marker prevents closing that reused handle
number again. Process death makes the driver unregister its rings;
the service manager calls `RecoverAfterCrash` with the journaled name and GUID
under its ownership lock, as in system design section 2. Hosted tests confirmed
that process death alone leaves a phantom node: the cleanup hook recreates that
same identity through the DLL and closes it normally. It refuses to take over a
present adapter. `DeleteDriver` is an explicit installer operation only;
ordinary cleanup never removes a shared driver.

The DLL is loaded once from beside the executable, verified before loading and
held open without write/delete sharing. Dependencies load from System32 only.
It stays loaded because its adapter API queues asynchronous cleanup callbacks.

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
in the distribution. Our path must have zero round trips over 50 ms.

Throughput uses delivered UDP bytes over a fixed interval and complete, hashed
TCP transfers, with one and eight streams. The UDP load generator is a separate
process, so it does not compete with only the Go session for Go scheduler slots
while the DLL executes outside that limit. Three trials alternate implementation
order. Each TCP stack first runs two fixed, logged warm-up transfers: CPU profiles
show both implementations' initial connections warming from roughly 320–450 to
540–600 MB/s on the same x64 runner. The three measured trials compare the steady
state of a long-lived engine. All measured samples remain in the comparison:
a DLL `ERROR_INVALID_DATA` is logged
as a baseline failure, its partial UDP goodput (or zero for an incomplete TCP
transfer) is retained, and a fresh DLL session is used only for the next metric.
No failed sample is retried into a pass. The locked design's 10% performance
regression gate applies to the medians. Packet corruption in delivered data,
unknown reference errors and failures of our session fail CI.

Parallel senders verify every test payload. Deterministic malformed-entry tests
independently prove recovery, even if the driver corruption does not occur in a
particular stress sample. Lifetime tests count process handles and their kernel
object types after warming Go's OS-thread cache (six handles per Windows thread),
measure private memory after GC/scavenging, and enumerate PnP
records without filtering out non-present devices.

- [Windows high-resolution timing](https://learn.microsoft.com/en-us/windows/win32/sysinfo/acquiring-high-resolution-time-stamps)
- [Process handle snapshot ABI reference](https://github.com/winsiderss/phnt/blob/master/ntpsapi.h)
