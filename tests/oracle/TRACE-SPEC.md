# Controller trace contract, version 1

The original reference is Node main `0172a6bf345e739ce1854d732934bd5ee9c713db`.
The original fourteen traces were recorded with the verified behavior-neutral
factory at `be5eaea484f97b8e8fdcd68f787946411fc0f819`. The eleven added traces use
the Node source and recorder at `59f2d9576341c0cb15e115ee0f9dbb99e44aab0d`.
`provenance.json` gives the baseline, recorder commit, observation hooks and
byte hash for every trace. It overrides the stale baseline headers while keeping
all 25 fixtures byte-for-byte unchanged. New recorder output uses these corrected
headers. The original unmodified-server oracle remains the factory's regression
gate; observation hooks never replace production statements.

The eleven added traces use a corrected directory-list callback and extra
observations at LineHealth.noteProbe and buildState entry, as named in the
sidecar. The original fourteen retain their original harness behavior.

Each trace has `version`, `baseline`, `name`, `scenario` and `entries`. Each entry
has a zero-based contiguous `seq`, `direction` (`input` or `output`), `kind` and
`value`. Array order is significant. Replay rejects the first differing entry;
it does not sort, deduplicate, coalesce or discard events. The scenario is the
external driver, and entries also freeze all resulting internal I/O completions.

## Inputs

- `initial-files`: the settings document supplied before startup.
- `http`: method, route, body when present and header overrides. Default Host and
  X-Token come from the recorded in-memory session file.
- `helper-line`: the exact newline-free JSON string; the real Node meter/outside
  parser receives it. A malformed line must remain observable as an input.
- `interfaces`, `connections`, `probes`: the next OS address/engine snapshots or
  probe answer supplied by the environment. They remain in effect until changed.
- `adapter-snapshot`, `counter-sample`, `engine-reply`, `probe-result`: values
  returned at each boundary, including null and failed probe status.
- `clock-tick`: absolute UTC epoch milliseconds. Timers execute at their scheduled
  fake time, with insertion order breaking ties; microtasks drain before the next
  timer. The test timezone is UTC unless a scenario explicitly specifies another.
- `file-completion`: operation, path, success and error code. Temp paths stay
  deterministic. `completion` records the monotonically numbered boundary
  completion and its kind at that exact position in the stream.
- `async-result`: operation, arguments, success and returned value (with an
  explicit undefined flag), or error details. This covers platform/helper calls,
  engine response bodies, installed-app lookup, log writes and update checks.
- `socket-completion`, `process-exit`, `timer-completion`: fake listener/close
  callbacks, child exit and resolved delays. Pending operations have no completion.
- New scenarios also record `directory-list`, `probe-vote`, and `state-snapshot`.
  The snapshot boundary is when the response is built, not when its bytes are
  sent: a probe can finish between those two points. Replay dispatches that
  round on the recorded side of the snapshot and checks the next response too.

The initial harness clock, entropy, paths, PID, socket ports and platform are
deterministic. No live adapter, clock, helper, HTTP service or engine contributes
input. The VM import whitelist rejects unexpected host dependencies.

## Outputs

- `api`: status, headers and the complete parsed JSON, with explicit nulls.
- `event`: each event when appended, including id, time, line, kind and text.
- `engine`: route, HTTP method and JSON command body (including lane PUTs and
  connection DELETEs); `spawn` holds the fake executable and its arguments.
- `write`: final path, UTF-8 byte count, SHA-256 and text except for large share
  files. Atomic temp writes are observed through file completions; the final
  rename records the committed file. `remove` records deletion.
- `outside-close`: validated connection selectors passed to the OS boundary.
- `log`, `console`, `exit`: diagnostic line or exit code.

The Node regression checker permits **no differences**. JSON non-finite numbers
must serialize to null exactly as Node does. Lists and line priority stay ordered.

## Go comparison: permitted representation differences

The future Go trace adapter may canonicalize JSON object-key order EXCEPT
`appLines` and `shares`: compare these as ordered `[key, value]` entry lists
everywhere (including settings writes). Pin order decides which saved version
wins; share order decides port slices. Never canonicalize these keys or any
array order, field presence, null, boolean or numeric meaning. Node engine config
and rule-file bytes must still match while using the sing-box adapter.

Only these fields may be mapped, consistently across the whole trace:

- generated event ids and temporary-file/session random ids, through a bijection;
- `/oracle` to the test's isolated root and executable/PID/port identities to the
  corresponding fake resource;
- absolute timestamp origin, preserving offsets, deadlines, local-time periods
  and ordering. With injected fake clocks the default is exact equality.

Log wording may differ in Go, but each logged condition must match its boundary,
severity, relevant line/app/operation and failure details. An adapter must supply
explicit per-condition mappings; blanket log omission is forbidden. These are
comparison rules, not changes to the frozen Node files.

## Deliberate 1.0 differences (locked design 4.4)

1. Combining uses a per-flow sequence instead of source-port slices.
2. Line checks use three operators and real-traffic evidence.
3. Crash recovery uses the lease, reattachment and journal.
4. Settings persist before the engine changes.
5. Network changes close only flows on the affected line/address.
6. TIME_WAIT follows the validated new-engine behavior.

### Milestone-one fixes and explicit lifetime choices (round four)

- PID cleanup fixes a 0.3.x race: the child exit goroutine is its single awaited
  owner. Stop and Start wait even when the child has already exited but cleanup
  is unfinished. A missing PID file is success; a failed delete logs a cleanup
  warning and does not fail Stop or Quit. Replay omits only Node's second
  removal of that same exited child's PID file, retaining the first removal and
  all other output ordering. The original fixture bytes remain unchanged.
- Network snapshots are ordered by a Control-owned monotonic sequence, allocated
  before one-shot reads and on streamed delivery. Worker restarts and backwards
  wall-clock steps cannot freeze the adapter list. The read timestamp remains
  freshness evidence, never the ordering authority. Route votes use that same
  sequence to count each snapshot once.
- Node discards a first lane acknowledgement when wanted() initializes a lane
  and changes its generation during the switch. The port preserves that retry
  for newly unsampled lanes. Startup explicitly performs Node's initial health
  sample before supervision, whichever Go loop is scheduled first.
- An HTTP panic is fatal: it logs the panic and stack, stops routing, and ends
  Control. Returning a 500 and continuing could use a partially mutated routing
  transaction. Returned action errors keep Node's ordinary HTTP responses.
- Accepted mutations, including setup, app/line actions and settings, belong to
  the service context; closing the browser does not cancel them, as in Node.

`undo.json` adds six focused cases from the unchanged Node production source at
`4e8b74a0513e6c0ecbaac0282df9e7fa11ea4128`, with only initial-file and failure
injection added to the harness in round four. Both Node and Go check damaged
policy/metrics, policy restore and save failures, an ordered partial restore,
and a legacy empty metric record. The comparison includes HTTP status/error,
saved Undo, policy, diagnostics and ordered OS calls (including the refresh).
These cases supplement the 25 full traces; they do not replace them.

### Milestone-one adapter limitation (owner decision, 2026-10-19)

Control uses `apply revision -> acknowledgement` and persisted closure intents
with `startedBefore` now. The temporary sing-box adapter retains Node's serial
rule-file writes, per-file reloads and rollback. It waits the legacy 300 ms reload
grace period, checks engine availability, and awaits selector PUT responses before
acknowledging; sing-box exposes no atomic rule-set acknowledgement. This does not
prove packet-level atomicity or that a stalled file watcher has reloaded. Closures
must wait for the adapter acknowledgement. Golden file bytes remain unchanged.
The real engine replaces this limitation with atomic revision application in
milestones 3–4. It is not permission to discard failed applies or early closures
from replay. Journal writes and settings-before-apply ordering are explicit 1.0
outputs, separate from the frozen Node writes.

The milestone-one journal retains revision numbers and closure intents, with
fsync before replacement under the apply mutex. The unused desired/settings
copies are removed; settings remain the authoritative desired state. A failed
journal write is logged prominently and cannot prevent a lane switch. Pending
closures retain their original cutoff in memory, retry independently at 2, 5,
15, 30, then at most every 60 seconds, and do not cause new revisions while
waiting. This is recovery metadata, not a prerequisite for live failover.

The replay names the ordering changes imposed by that revision boundary:
settings and their backup move ahead of the immediately preceding rule batch;
lane and share-change diagnostics wait for the whole batch acknowledgement;
and a statistics read that Node completed during queued rule writes completes
after that acknowledged batch in Go. These are bounded adjacent-operation
mappings. They cannot move a closure, API response, event, or another policy
across the batch, and they cannot reorder, drop or coalesce rule-file writes.

### Milestone-one line-check expectations

The defaults are Cloudflare `1.1.1.1:443`, Google `8.8.8.8:443`, and Quad9
`9.9.9.9:443`, rotating per check. Quick checks have a 3 s deadline. A failed
quick check is confirmed by parallel full checks against two different operators
(the other two defaults); each has a 10 s deadline. Full checks never follow
redirects and retain normal TLS certificate verification for the address.

- Cloudflare: `/cdn-cgi/trace`, HTTP 200, `text/plain`, and `ip=` in the body.
- Google: `/resolve?name=example.com&type=A`, HTTP 200, `application/json`, and
  numeric JSON `Status` equal to zero.
- Quad9: `/dns-query?dns=<fixed example.com IN A query>`, HTTP/2, HTTP 200,
  `application/dns-message`, with the same media type in `Accept`.

Two different hosts reached by new connections in the preceding 30 s suppress
checks while a line is healthy. Recovery of a down line still requires full
HTTPS checks. Busy-line suppression remains unchanged. `engineUnavailable`
does not add a failure or a pass. User targets replace the default set. The
inherited Node default pair denotes the new three-operator defaults; an explicit
target edit atomically stores `probeTargetsCustom` alongside the list, so even
an explicit choice of that old pair remains a two-target override after restart.
That internal settings marker does not add a field to the HTTP state contract.

Each complete failed round contributes one vote. `probeFailover` goes down at
26 s and recovers at 41 s, exactly as recorded, with no timestamp or ordering
remapping. Each route snapshot counts once, at five-second spacing, after the
current health sample. `lostDefaultRoute` proves the second missing route read
at 10 s takes effect on the 11 s poll; recovery follows the 15 s read.

Custom targets use HEAD, do not follow redirects, and accept every HTTP status,
as the v1.14.2 URL test does. An explicit list replaces the operators, even when
it contains an operator's address. The three product defaults retain their
exact content criteria. The only state-field mapping adds Quad9 to the
inherited default pair so the window shows the sites actually used. Explicit
target lists are compared unchanged; their internal persistence marker is
checked separately and omitted only from the Node settings-file comparison.

Keep these in separate, explicitly named acceptance expectations. Do not edit
Node goldens to make new behavior look like parity. The freeze, DNS drop and cap
hang are `baseline-defect` packet-level gates; this fake-engine suite neither
reproduces nor declares those defects fixed. Main-line cap exemption, blocked
secondary lines, failback without automatic close, and shared Reconnect keeping
routed flows remain required parity.

## Coverage and limits

Traces cover physical and probe failure/recovery; a busy line ignoring failed
checks; Santiago's nonexistent midnight on 6 September 2026; saved-version and
legacy case-colliding app choices; exhausted lines moving or
becoming blocked; main-line exhaustion with no stand-in, also while combining;
pinned/shared Reconnect
with outside sockets; weighted combining; IPv6 settling and restarts; and legacy
line/Undo migration with an unknown settings key. Outcome assertions run before
recording, so a trace cannot silently freeze an unexercised scenario.

Run `node --test test/traces.test.mjs`. It reports the actual Node executable,
version and SHA-256. Regeneration prints JSON with `traces.mjs`, using the same VM
flags as `record.mjs`; it never overwrites fixtures.

Run `go test -v -run TestRecordedTraceReplay ./internal/control` for the Go
consumer. All 25 traces, 7,894 entries and 3,003 completion records are checked.
The real Go controller and sing-box adapter run with an in-memory filesystem,
fake clock/process and recorded engine replies. Replies are consumed in their
recorded order; unexpected calls and leftover replies fail the test. Comparison
covers all 64 API outputs through the real HTTP handler (status, headers and
body), ordered engine requests, events, control writes,
config/rule SHA-256 values, removals, spawns, outside-close selectors and logs.
`appLines` and `shares` retain their ordered-entry comparison. A combined output
ledger also compares ordering across these kinds, with only the explicit
revision-boundary and default-site mappings above. Initial usage saving and
the minute timer complete at the recorded startup and same-deadline boundaries.

The two startup diagnostic mappings replace the missing-PowerShell-helper
messages with the corresponding native-worker messages. Other recorded log
conditions retain their order and details; none are dropped. Journal writes
have separate persistence/acknowledgement tests because they do not exist in
the Node baseline. Node filesystem/platform completion bookkeeping is checked
for valid kinds, contiguous sequence IDs and matching completion boundaries;
the equivalent Go filesystem and helper work is injected directly.

The original 14 traces are unchanged. Eleven new traces cover line add/remove/
order, app choices, routing off/on, settings and autostart, all setup and update
actions, cap reset, a hung engine, lost default routes, adapter rename and a
failed Quit. Their directory stub returns actual names (the old recorder's
callback error remains frozen as a failed directory read in the old traces).
The new installed-app fixture includes the real provider's `hasIcon` field.

Every HTTP endpoint is exercised (the 17 control routes, plus ping and icon):

| Routes | Traces |
| --- | --- |
| GET state | All state scenarios |
| GET ping, installed-apps, icon (missing icon) | routingAndReads |
| POST lines/add, lines/remove, lines/order | lineAdd, lineRemove, lineOrder |
| POST lines/update | combining, capMoved, capBlockedAndMainException |
| POST app-line | appLine |
| POST routing | routingAndReads |
| POST combine | combining |
| POST reconnect | reconnectPinned, reconnectShared |
| POST settings | settingsSetupUpdate |
| POST setup/cable-default, setup/keep-both, setup/undo | settingsSetupUpdate |
| POST update/check, update/dismiss | settingsSetupUpdate |
| POST quit | migration, quitFailure |

Log conditions compared include startup/status/retry transitions, added and
removed lines, line ordering, rebind and IPv6 restarts, hung-engine restart,
speed-read failure, physical/probe/default-route failure and recovery, busy-line
suppression, cap exhaustion/reset/blocking/closure, combining shares,
Reconnect counts, autostart on/off, available/failed updates, migration, and
successful/failed Quit. `Run()` tests additionally execute concurrent native
worker streams, polls, supervision and API work through the real adapter under
the CI race detector. Fatal poll/supervisor/probe/stream tests require cleanup
and a logged failure, rather than merely recovering a panic.

Separate adversarial tests cover a late probe, an old connection reply after
stop, a completed rebind racing the supervisor, concurrent settings/state/
counter updates, failed file replacement with rollback, failed apply without
closure, and retrying a closure without admitting newer flows. Reconnect also
persists its selected IDs and original cutoff before calling `closeFlows`; the
adapter uses that existing poll's UUIDs, preserving Node's DELETE sequence.
These tests add
coverage beyond the original immediate-completion traces. Windows kernel
behavior remains in the hosted Windows parity and real-engine CI jobs.
