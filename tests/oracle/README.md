# Frozen Node oracle

Recorded before changing `server.mjs`, from main commit
`0172a6bf345e739ce1854d732934bd5ee9c713db` (0.3.1).

`node.json` freezes the actual HTTP handler's status, headers and JSON for all
11 tray scenarios and every API action. It also records validation/auth failures,
settings and Undo writes including their backups, usage, engine config/rule
writes, selector PUTs, connection DELETEs, process arguments and logs in order.
Share files contain thousands of ports: their exact UTF-8 length and SHA-256 are
recorded instead of repeating their contents. Other writes include their bytes
as text as well as the digest. No fields are stripped from API JSON.

Run `node --test test/oracle.test.mjs`, or `npm test`. The test runs the recorder
in a separate Node process with `TZ=UTC` and VM modules enabled. Existing Windows
and Linux CI jobs run it through `npm test`.

To inspect a fresh recording, run:

```
node --experimental-vm-modules --disable-warning=ExperimentalWarning tests/oracle/record.mjs
```

Set `TZ=UTC` first. The recorder prints JSON; it never rewrites the frozen file.
Review a difference before updating anything. Use the file editing tool to save
an explicitly approved baseline, never an automatic snapshot-update mode.

## Isolation and limits

The VM loader reads repository source, but the loaded server cannot read or
write the host filesystem, listen on a host socket, spawn a host process, change
Windows settings or send a network request. Unknown imports fail closed.
The real settings, usage, apps, lane, line-health and engine modules run inside
the VM. File operations are in memory; clock, entropy, adapter snapshots, socket
listeners, child processes, engine replies and Windows operations are fakes.
Binary checksum verification is bypassed only on the VM's Engine prototype.
Real engine verification, networking and installation remain CI acceptance gates.

The tray examples contain deliberately invalid/long display data (including
non-hex line ids). `hooks.txt` appends observation/setup exports to the source in
memory, without replacing any original statement. It seeds those presentation
scenarios after startup; they are not settings-load/migration tests. State JSON
comes from the real handler and `buildState`, not the tray example's object.
The route journey instead uses valid persisted settings and real transitions.

These fixtures prove controller behavior under the stated inputs. Fake Windows
operations do not prove Win32 behavior, the fake engine does not prove packet
routing, and the fake installed-app/update services do not prove discovery or
GitHub. Their existing tests and CI gates remain necessary. This is the oracle
portion of milestone 0, not the Windows second-egress or Linux namespace harness.
