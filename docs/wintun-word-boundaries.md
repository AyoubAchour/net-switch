# Wintun word-payload boundary capture

This is test evidence only. Build the test executable with
`-tags=wintun_boundaries` and set `NETSWITCH_WINTUN_BOUNDARIES=1`. Normal product
builds have constant-false hook guards and no observer state. The existing
`wintun_integrity` diagnostic is separate and cannot be enabled simultaneously.
The release guard checks both tags and their hook symbols.

The unchanged word-v1 payload uses one immutable 64 MiB socket write per stream,
32 KiB receiver reads, and the process-owned 512 MiB bank introduced in #93.
There are four internal checks, plus the existing Windows verifier:

- `ring_ingress`: the private copy, before validation and gVisor delivery.
- `echo_read`: bytes returned by gVisor to the echo application, before writing.
- `stack_write`: borrowed gVisor packet views in `Link.WritePackets`, before the
  queue copy. No packet/view is cloned, released or retained by the observer.
- `ring_publish`: native Receive-ring bytes after all copies in a batch and
  immediately before Tail publication. DLL mode observes native bytes before
  `WintunSendPacket`; its opaque slot offset is explicitly -1.
- `host_receive`: Windows' existing word verifier. Its first differing read
  immediately snapshots histories, rather than waiting until transfer end.
  A bounded final record supplies the eventual bad-run length/realignment.

Only the dedicated IPv4 TCP test tuple is inspected. Client ISN comes from SYN;
server ISN comes from SYN-ACK, whose ACK must match that SYN. Payload bytes never
define an ISN or expected offset. Sequence subtraction handles 32-bit wrap and
SYN consumes one sequence number. Each packet/view edge handles partial words;
the body compares full 64-bit encoded words with no reference payload.

`retransmit_or_overlap` means a payload starts below the highest end offset
previously observed at that boundary; it is not an assertion about a TCP timer.
Every record includes sequence, flags, payload length, logical offset, slot,
batch ID and position where those exist. Source attribution requires three
consistent decoded words; arbitrary bit damage can remain unattributed.
Slot offsets identify the four-byte entry header relative to `Ring.Data`;
packet bytes begin four bytes later. Batch positions count accepted slots.

Evidence is bounded: 16 flow incarnations per fixture, 64 history records per
flow per internal stage, 128 coverage intervals per stage, and eight failure or
incomplete-evidence emissions per executable run. A first host failure may add
one final run-length record. Later failures still fail the run even when their
detail is suppressed. Histories are rolling context, not a complete packet
trace. Success prints only transfer coverage summaries. Coverage requires an
exact union covering every payload byte at every internal stage; missing SYNs,
unbound/reused tuples, parser failures or exhausted coverage budgets are
incomplete evidence, never clean credit.

A first bad `stack_write` with good `echo_read` narrows the fault to the TCP send
path. Good stack bytes followed by bad ring-publication bytes implicate the
queue/copy interval. Good publication checks followed by bad host bytes locate
the fault after publication, including the driver, Windows stack and host read;
they do not alone prove a specific driver race. A bad echo read after good ring
ingress exposes receive-side corruption that would otherwise be blamed on send.

No packet is changed, dropped or repaired by a hook. In particular, the existing
validated-prefix return and session-recovery behavior is unchanged.
Unexpected ring-rejection counters still fail a diagnostic/sample even if
retransmission repairs the stream. They are reported separately from delivered
word mismatches, and the pilot retains raw child recovery warnings.

## Pilot and subsequent hunt

Dispatch CI with `wintun_integrity=true`, `wintun_integrity_scenario=boundaries`.
This selects exactly two jobs: x64 and ARM64. Each runs eight alternating pairs
for ours and DLL, with separate untagged/tagged child executables, identical
process/adapter lifetimes and two fixed warmups. Throughput, timed process CPU
and peak working set are reported. A ratio below 0.80 fails the pilot; failed or
slow samples are never replaced. This baseline includes #93's word verifier,
not the older SHA-only payload. There is no diagnostic callback cost in the
untagged baseline.

The separately selected `boundaries-hunt` input defaults to one replica per
architecture. Expansion additionally requires `wintun_boundary_shards=2` or
`5`, with a single cap of ten concurrent jobs. The pilot always stays at one
replica per architecture regardless of that input. It runs two full performance suites
against each reference (DLL and in-process). Do not dispatch it until the pilot
numbers have been reviewed and the hunt explicitly approved. This PR's initial
dispatch is the two-job pilot only.
