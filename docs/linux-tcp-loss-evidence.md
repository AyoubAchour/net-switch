# TCP buffer demand and loss evidence

The buffer case requires all 64 downloads to deliver at least 5 MiB in every
200 ms window for two continuous seconds. This proves offered demand; the
separate budget checks require growth to fill 256 MiB to within one grant,
stay there, and never exceed it. Integrity and all 64 open flows remain required.

Each wave now offers five seconds instead of 3.5 seconds. No connection is
retried. Every report also gives the verdict calculated from the first 3.5
seconds of each download. This is a prefix comparison of the measured run,
not a claim that a separate run with different wave scheduling would be identical.
The memory-pressure case keeps its allocation live throughout the longer load.

The failed Ubuntu 24.04 x64 sample on `273f18` remains a failure: run
39449703886, job 118720930983, download 38 transferred 762,511,360 bytes in
3.5 seconds, but its longest qualifying stretch was 1,850 ms. The engine
recorded one RTO and no counted TUN, transport or kernel-interface drops.
Those aggregate counters do not establish where the segment or its ACK was
lost or delayed. They do not establish that the harness caused the loss.

## What the next run records

Both buffer cases write `tcp-loss.jsonl` alongside their case log:

- Before traffic, at wave boundaries, after an observed RTO, and before
  release: both ends of every veth, the TUN, all three routers, and the server
  namespace. Each snapshot includes detailed `ip` link counters, every qdisc
  and class (including any shaping), SNMP/TcpExt counters, and `ss -tinmo`
  socket queues, retransmits, timers and memory/drop counters. Softnet counters
  are host-wide per-CPU observations, not independent per-namespace losses.
- Once a second and whenever an RTO changes: the engine's existing per-endpoint
  retransmits, RTOs, receive-buffer/segment-queue drops, checksum/send errors,
  buffer usage and grants, RTT/RTO and congestion state. Snapshots add no
  persistent per-flow memory or idle workers. Above 128 endpoints the stats
  response reports an omitted count instead of walking the full flow cap.
- The app tuple and native socket's local address join the app result, the
  engine endpoint and the kernel socket records. All 64 held downloads must
  have an engine snapshot; missing topology observations are hard failures.

The engine's TCP RTO belongs to its **app-facing** gVisor endpoint. Its native
socket and the server use a separate TCP sequence space and separate kernel
retransmission counters. Compare deltas within the same leg and time window.
Engine receive-queue drops indicate an engine-side loss; interface/qdisc drops
name the namespace and device; socket drops name the kernel endpoint. Zero
drop counters cannot exclude delayed scheduling, delayed ACKs or an uncounted
drop. Snapshot start/end times are recorded because the kernel reads are not
atomic and do not prove a particular packet's route.

Counter interpretation follows the [Linux interface statistics documentation](https://docs.kernel.org/networking/statistics.html),
[Linux SNMP counter documentation](https://docs.kernel.org/networking/snmp_counter.html),
and the [tc](https://man7.org/linux/man-pages/man8/tc.8.html) and
[ss](https://man7.org/linux/man-pages/man8/ss.8.html) manuals. The implementation
uses existing gVisor endpoint counters without modifying the generated tree.
