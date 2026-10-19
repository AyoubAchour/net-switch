# Controller trace contract, version 1

The reference is Node main `0172a6bf345e739ce1854d732934bd5ee9c713db`.
The unmodified-server fixtures were committed first; the factory must still pass
them without changes. Traces use that behavior, including its defects.

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

Keep these in separate, explicitly named acceptance expectations. Do not edit
Node goldens to make new behavior look like parity. The freeze, DNS drop and cap
hang are `baseline-defect` packet-level gates; this fake-engine suite neither
reproduces nor declares those defects fixed. Main-line cap exemption, blocked
secondary lines, failback without automatic close, and shared Reconnect keeping
routed flows remain required parity.

## Starter coverage and limits

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
flags as `record.mjs`; it never overwrites fixtures. All current fakes resolve in
deterministic order. Adversarial delayed/reordered completions and a Go trace
consumer remain work for the full controller port; these traces do not prove
those races safe. Windows kernel behavior stays in real-engine CI.
