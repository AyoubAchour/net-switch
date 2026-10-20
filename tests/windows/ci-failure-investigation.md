# Windows HTTP failure investigation

20 October 2026. The two original failures remain real failures. A passing
repeat does not prove either cause has been fixed.

| Failure | Established by the original evidence | Root cause |
| --- | --- | --- |
| TestISP reset | Loopback control HTTP; no app or sing-box running | Unconfirmed |
| Cap setup | Secondary HTTP setup; one reply reached sing-box, but the failing client socket is unidentified | Unconfirmed |

## TestISP localhost reset

[Run 39336173889, attempt 1, job 118346106447](https://github.com/AyoubAchour/net-switch/actions/runs/39336173889/attempts/1)
failed at 23:24:08 UTC in `direct uplink baseline`: a `/stats` fetch failed with
`read ECONNRESET`. The report lost the nested error and did not distinguish the
request before the HTTPS probe from the request after it.

The gateway log contains its ready message and no panic or session error. Its
final counters were written on shutdown: zero TestISP errors, zero upstream
errors, and only background NetBIOS traffic through the virtual interface.
No app or sing-box process is involved in this proof case. The failing path is
the harness's loopback HTTP control connection, not a request routed through
the Wintun ring. These facts do not identify which end reset the connection.

[Attempt 2, job 118368537462](https://github.com/AyoubAchour/net-switch/actions/runs/39336173889/attempts/2)
passed on the same commit `5f2a39856f575ef90997c4d9c04b6b4b9810c408`.

## Cap setup timeout

[Run 39334336226, job 118339909824](https://github.com/AyoubAchour/net-switch/actions/runs/39334336226/job/118339909824)
failed at 22:43:17 UTC, 9.084 seconds into the cap case. It only reported the
client's eight-second `AbortError`, without the request's identity or phase.

The saved gateway trace shows a controlled HTTP request at 22:43:09.921 UTC,
a 243-byte reply at 22:43:09.922, and an acknowledgment of the whole reply at
22:43:09.962. Its tuple was `50362 -> 60584`; the reset arrived during teardown
at 22:43:18.034. This new controlled request places the failure in the secondary
HTTP setup: the two main-line HTTPS requests must finish before that step starts.
There was no global gateway stall: at least one setup request
completed that leg. The client opened two secondary requests concurrently,
so the old trace cannot identify the missing request or locate its stall.
The trace stops at sing-box's outbound socket; it does not prove delivery to
the application's client socket.

The whole workflow was later cancelled, but this job's conclusion is
**failure**. There is no successful Windows run on its exact commit
`8a6c8aaa8dec586d7db23f6d9560fee2ae0a6721`: both Windows jobs in the push run
were cancelled, and the successful same-commit “Acceptance” workflow ran Linux.
The later successful Windows jobs cited in #41 contain additional diagnostics.

## Changes and verification

The harness now retains HTTP connection/request timing, request identity,
socket ports and byte counts, response phase, process exit state, engine connections, gateway packet/session
diagnostics, responder observations, and the last app, engine and gateway log
lines. It starts diagnostic reads together so a slow app API cannot erase the
short packet history before it is captured. The client preserves the first
error even if aborting the request also produces a stream error.

Gateway logs use UTC. Go's HTTP server deliberately
[expires a read deadline to cancel its background reader](https://github.com/golang/go/blob/go1.27.2/src/net/http/server.go#L785).
A logged read timeout alone is not a failed request: compare its deadline,
request/response events, byte counts and connection close.

A regression test uses two real loopback HTTP requests, completes one and
stalls the other's body. The unchanged eight-second deadline must fire, and
the report must identify the stalled request's nonce, local port and response
phase. It does not start the app, engine or a virtual adapter.

The original request deadlines and pass/fail rules are unchanged. There are
no retries. Neither frozen 0.3.x product code nor `internal/wintun` is changed.
No product or driver fix is claimed without a reproduced cause.

## Bounded repeats

- [39379855692](https://github.com/AyoubAchour/net-switch/actions/runs/39379855692):
  **0 failures in 12 TestISP proof runs** (six per architecture).
  Four full acceptance runs passed (one x64, three ARM64), including cap setup.
  The second x64 run failed its initial clean-machine check because the previous
  0.3.1 run left its known non-present `sing-tun Tunnel` device. It never reached
  the cap test and is not counted as a cap failure or a pass. This repeat-design
  error remains a failed job; the clean-machine assertion was not weakened.
- [39381331454](https://github.com/AyoubAchour/net-switch/actions/runs/39381331454):
  **0 resets in 200 fresh Node clients / 400 control requests**. Each client sent
  two requests. The slowest pair took 291.44 ms on x64 and 274.91 ms on ARM64.
  The parallel-request diagnostic regression ran once per architecture and
  passed, taking 8.10 and 8.22 seconds.
- [39382556940](https://github.com/AyoubAchour/net-switch/actions/runs/39382556940):
  **0 failures in 200 cap setups** (100 per architecture), within one acceptance
  session per job. Both full suites and the diagnostic regression test passed.
  Each suite retained 19 harness passes, 22 parity passes, 12 confirmed baseline
  defects and the existing three deferred cases.

The temporary dispatch job and repeat switches are removed. No local network
tests or app processes were run. Both original root causes remain unconfirmed;
the change fixes missing evidence, not the underlying intermittent failures.
