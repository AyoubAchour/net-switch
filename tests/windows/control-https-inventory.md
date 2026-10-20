# Control HTTPS dependency audit

20 October 2026. Scope: Control's tests and an inventory of the other workflows'
network assertions. The separate acceptance and TestISP proof suites are not
changed here; their public egress checks need individual decisions.

## Control changes

| Check | Old destination | New destination |
| --- | --- | --- |
| Three pinned TUN sockets on bb | `1.1.1.1:443` | Local TLS, through the TUN and TestISP |
| Rewritten app rule: new aa sockets, reuse old bb sockets | Same | Local TLS |
| 100 aa sockets before/after selector PUT, then three new bb sockets | Same | Local TLS |
| Five held sockets during DNS change, new socket after restoring DNS | Same | Local TLS |
| Proxy routing: default (3), pinned (3), combined (12), pinned while combining (6) | Same | Local TLS through the selected Control proxy |
| Real internet egress through the Control proxy | Previously implicit in every request | Exactly one independent public trace request |

The TUN client still connects to `203.0.113.44:443`. The same non-final
`route-options` rule used by the engine fixture changes only the destination.
The app's own process rules, selectors and interface-bound outbounds choose
the route. Config comparisons reject any other change. TestISP destination
counters require +3 for the first bb sockets, +0 for the 100 aa sockets and +3
for the new bb sockets. Engine metadata must identify the copied client, its
source port, `tun/tun-in`, and the expected line. Refresh checks require the
same client port, a reused socket and the same TLS responder connection ID.

No assertion deadline or request concurrency was increased, and no retry was
added. There are 20 ordinary product-config lifecycle cycles after the traffic
fixture. The original DNS-change observation remains an observation, not a
newly claimed assertion that sing-box preserves those connections.

The retained public request uses `https://1.1.1.1/cdn-cgi/trace`, verified TLS
and an `ip=` response. It proves external internet egress, which a same-runner
responder cannot prove. HTTP 5xx and resets have the distinct
`public target unavailable` label and still fail the test. They are never
retried or counted as a pass.

## Other public traffic: follow-up decisions

| Workflow / case | Target | Local replacement without losing the stated proof? |
| --- | --- | --- |
| CI Windows acceptance: physical and TestISP public egress baselines | `https://1.1.1.1/cdn-cgi/trace`, one on each path | **Keep public.** These explicitly establish real internet on both independently bound paths. |
| Windows acceptance: pins on both interfaces; old sockets after a pin change; 40-flow combining | `https://1.0.0.1/cdn-cgi/trace` | **Can move local.** Keep actual interface counters and original-socket identity. Do not replace their preceding public egress baselines. |
| Windows acceptance: route-withdrawal/dead-gateway failover and restoration | `1.0.0.1:443` for fresh traffic, plus product health endpoints below | **Traffic can move local.** Keep real internet health/failover evidence public; a reachable local machine does not prove an ISP is working. |
| Windows acceptance: main-line held sockets during cap exhaustion, and main-line exception after the rejection burst | `1.0.0.1:443` | **Can move local.** The proof concerns connection survival and cap policy, not internet reachability. |
| Windows acceptance: control crash restores direct connectivity | `https://1.1.1.1/cdn-cgi/trace` through normal Windows routing | **Keep public.** It proves usable internet after the TUN disappears, rather than only local reachability. |
| CI TestISP proof: direct uplink baseline and TestISP egress/reverse relay | `https://1.1.1.1/cdn-cgi/trace` | **Keep public.** Both are explicit internet egress proofs; preserve the TestISP destination/byte counters. |
| TestISP proof: pause/drop, route withdrawal, direct-only firewall block, unaffected path and recovery | Same | **Can move the fault assertions local**, after keeping the public baseline on both paths. A replacement must still depend on the selected interface's default route; a local host route would invalidate withdrawal coverage. |
| Product background health while Node Control/acceptance runs | `https://1.1.1.1/cdn-cgi/trace`, `https://8.8.8.8/`; native quick checks use their port 443 | **Keep for real internet health/failover coverage.** They are product behavior, not one-shot test requests. This PR does not change frozen Node code or suppress its probes. |
| Product background health while Go Control runs | `1.1.1.1:443`, `8.8.8.8:443`, `9.9.9.9:443` (quick TCP and full HTTPS checks) | **Keep for operator/health coverage.** A local fixture could isolate unrelated traffic tests later, but would not prove external operator reachability. |

Every retained public dependency in that follow-up needs a distinct
`public target unavailable` classification for HTTP 5xx and resets, with the
endpoint and phase recorded. The acceptance client and TestISP probe currently
lack that label. Add it at the test-reporting boundary; do not waive a failed
case, retry it into green, or blame a public endpoint for an unproven engine
failure. Background health failures need correlation with independent public
baseline results; a generic failed health vote alone cannot identify a 5xx/reset.

Source locations: `tests/windows/acceptance.mjs`, `tests/windows/client.mjs`,
`tests/windows/testisp/proof.mjs`, `tests/windows/testisp/harness.mjs`,
`tests/windows/testisp/main_windows.go`, `lib/engine.mjs`, and
`internal/control/poll.go`. CI's Windows Node and ARM64 installer jobs also run
the shared proxy-routing script, so they receive the local conversion and keep
the same single public egress request.

## Addresses that are not external test requests

- `1.1.1.1` in `Find-NetRoute` inspects the routing table without sending traffic.
- The DNS-change fixture sets `1.1.1.1`/`8.8.8.8` as Windows DNS servers. Its
  explicit padded UDP queries already go to the local TestISP responder.
  The unused public UDP default/fallback in the TUN client was removed.
- Linux acceptance's `1.1.1.1`, `8.8.8.8`, and `9.9.9.9` are servers inside its
  isolated fake internet. They are not calls to Cloudflare, Google or Quad9.
- Oracle vectors and unit-test addresses are recorded/mocked inputs.
- GitHub Actions, GitHub release/API/raw-content URLs, Node, Go, Wintun, npm,
  Ubuntu package mirrors and pinned Snap/Flatpak downloads are build inputs,
  not traffic assertions. Verified caches can reduce those dependencies;
  an echo responder cannot substitute for their packages.

## What the 99/100 failure actually shows

[Run 39469242976](https://github.com/AyoubAchour/net-switch/actions/runs/39469242976),
job 118788636733, used sing-box 1.14.2 on ARM64 with Node 24.21.0.
At the recorded head `f236281fdeb42ee725ef4d8dd082bb70edc6da96`,
`e2e-tun.mjs:192` asserts the size of `oldIds` **before** calling
`pointLaneAt('aa', 'bb')`. The preceding route check saw all 100 aa sockets;
the next connection snapshot contained 99.

The engine remained on, its PID file existed, and its warn-level log contained
no warning. The test did not record those 100 socket IDs/ports or FIN/reset
events. TestISP only observed bb, while these sockets used aa. Thus the retained
evidence cannot name the missing connection, identify its close mechanism, or
prove that Cloudflare closed it. It also cannot establish a selector-change
bug: the selector PUT had not happened.

Upstream [sing-box 1.14.2 selector code](https://github.com/SagerNet/sing-box/blob/v1.14.2/protocol/group/selector.go)
separately controls interruption of external connections. Source inspection is
not a substitute for reproducing the loss. The local test keeps the original
100/100 requirement and post-switch reuse assertions. New failure diagnostics
record missing IDs/ports and client FIN/error/close events before cleanup.

## Verification

The temporary dispatch runs ten fresh jobs per architecture, five Node and five
Go, with at most four jobs running at once. Each executes the full proxy-routing
and TUN test once. Results and final CI runs are recorded in the PR.
