# TIME_WAIT validation

The zero-timeout candidate is **unsafe** on gVisor
`v0.0.0-20261017122056-1b7906fdee8c`. The engine retains 60 seconds.
No gVisor patch is included. Immediate port reuse remains a release blocker.

Two wire-level reproductions failed on Windows amd64, 2026-10-19:

- Lose the final ACK after the engine closes first. The app retransmits its FIN
  from LAST_ACK. With the endpoint already removed, gVisor sends RST.
- Open another connection with overlapping sequence space, without timestamps.
  Replay the previous connection's data packet. The new connection reads `OLD!`
  instead of `NEW!`, despite the old packet's ACK belonging to the old connection.

The tests named `TestTimeWaitCandidateFails*` preserve those reproductions. Their
passing means the **candidate is still unsafe**, not that the acceptance gate
passed. Changing the dependency must rerun the whole gate before choosing a fix.

The remaining candidate tests cover 1,000 immediate reuses with payload hashes,
the 100 ms stall ceiling, timestamps on and off, 0/10/100/500 ms reuse delays,
100 MB transfer, sequence wrap, delayed SYN/data/RST and reordered old packets.
The large transfer runs without `-short` in CI. These are in-memory packets;
they do not create adapters, routes, firewall rules or privileged sockets.

## Deviation from the design

Section 5.1 makes timeout zero conditional on all gates passing. It failed.
The reviewed RFC 6191 forwarder alternative needs separate approval and review;
this implementation does not silently patch gVisor or enable an unsafe timeout.
