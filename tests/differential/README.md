# Pure-module parity

Build `./tests/differential/runner` with the Go version pinned in the root `go.mod`, then pass its executable to
`node tests/differential/run.mjs <executable>`. `ORACLE_SEED` changes the reproducible
random sequence. The Linux Go CI jobs build and run it; race checks run on Linux
and Windows x64. The runner is test-only and is never packaged.

The runner compares normalized lines, caps, shares, lane selection, sharing,
migrations, app keys and RE2 patterns, outside ids, release offers and local-time
period starts, persisted usage and repeated routed/outside traffic samples. It
checks numeric-key ordering and floating-point totals across changing lines.
It exercises seven timezones, coercions and damaged entries as well
as ordinary inputs. Unicode cases include every uppercase/titlecase code point,
contextual sigma/dotted-I casing, and a label cut between an emoji's UTF-16 halves.
Failures print the seed, case, input and both outputs. Non-finite numbers compare
as JSON null, matching Node. Generated migration ids use the same deterministic
entropy in both implementations; legacy deletions are represented explicitly.

## The named Node tests

The `node-tests.json` beside each package records public calls made by the original
Node tests, with their original names and expected results. The recorder executes
the original assertions first. Go runs those same calls as named subtests and
compares every result; line-health also compares state after every call. Only
identical stateless calls are deduplicated. Instance calls are never deduplicated.
The Node fixture-check test rejects drift when a source test changes.

Settings tests and the three port-distribution loops are direct Go translations,
with the same names. DST/month rollover, retry exhaustion and unknown-key tests
add coverage beyond the originals. Only the pure five update tests are ported;
the update HTTP client and architecture detection remain future control work.

## Integration seams

- `apppath.Rules` supplies separator, casing and version-folder rules. Windows is
  implemented; the Linux identity rules belong in the Linux platform port.
- `lines.MigrateSettings` returns changes; applying them must also delete
  `lines.LegacyKeys`. Unknown settings stay in the store. `settings.Delete` is the
  explicit equivalent of a Node update property set to undefined.
- `apps.Pins` preserves saved order, including the last version winning. Read it
  from raw JSON with `ParsePins`; settings Values/Change now expose this ordered
  type, migration/waiting-app placement retain it, and its JSON writer keeps it.
  Non-ordered map updates to appLines fail explicitly. `SharesFromWeights`
  returns a slice in JS property order, ready for `AssignPorts`. Both comparators
  turn appLines/shares into ordered entry lists before comparing.
- `usage.LocalLocation()` resolves the owner's zone. On Windows it reads the
  language-independent TimeZoneKeyName with GetDynamicTimeZoneInformation, maps
  it using the CLDR territory-001 pairs shipped in Go 1.27.2, and loads full IANA
  history from bundled time/tzdata. An explicit IANA `TZ` overrides that lookup.
  Unknown zone keys return an error; the controller should report it at startup
  and pass the resolved location to `usage.New`. Nil also resolves the zone,
  panicking on an error rather than silently using the wrong offset. Unix uses
  the complete system time.Local database. No Windows timezone setting changes.
  The Windows source documents the Microsoft API, and GO-LICENSE.txt retains
  the mapping source's license. Gap midnights use the pre-gap offset; folds
  choose the earlier instant, as JS Date does. Zone vectors include Santiago,
  Havana and Cairo and run under their recorded zones on every Go platform.
- Peak decay uses the specialized V8/fdlibm pow(0.5, exponent) calculation from
  Node v24.18.0, with its notices and license retained. Explicit rounding blocks
  ARM64 FMA fusion. Four hundred ingest sequences vary step sizes, idle samples,
  counter resets, cap periods and clock reversals; every peak and byte is compared
  exactly, with no tolerance or accumulating error allowance.
- `settings` retains unknown fields as RawMessage and exposes decoded values as
  float64. Writes are serialized, use a unique temp plus rename, then write .bak.
  Windows sharing/access/lock errors retry up to ten times with 50 ms waits.
  Numeric overflow is valid JSON, non-finite updates write null, and negative
  zero writes zero. Recovery lists invalid keys once, in default-key order.

These are library ports, not a running Go control service. Lane/start/setup queues,
the sing-box adapter, API service, supervised workers, Win32 parity, the Go trace
consumer, parameterized e2e launchers and full lifecycle integration remain for
milestone 1. No engine, installer, packaging or release behavior changes here.
