// Package stack configures the app-facing TCP/IP stack and its ordered link.
//
// TIME_WAIT remains 60 seconds to ACK a lost final ACK's FIN retransmission.
// The forwarder opts into tcp.SetTimeWaitHandler: any bare local SYN closes
// TIME_WAIT and reaches normal admission, regardless of sequence number.
// Remaining queued segments are dropped without resetting the new connection.
// The exported gVisor hook is independent of the engine and can also be used
// by the TestISP gateway with tcp.SetTimeWaitHandler(s, forwarder.HandlePacket).
//
// Callers must preserve packet order per tuple: one TUN reader or tuple shards,
// no IFF_MULTI_QUEUE, and ordered GSO segments (Link.InjectBatch). This relies
// on a local host never reusing a tuple it still owns. Forwarded/NAT clients
// require separate platform acceptance; the core tests do not prove that case.
//
// See TestTimeWaitImmediateReuse, TestTimeWaitLostFinalACK,
// TestTimeWaitThreeQueuedSYNsDialOnce, TestTimeWaitThousandPerSecondCap and
// TestPacketOrderPerTupleThroughLink. Reuse tests drive the real forwarder and
// flow table without waiting for endpoint removal. Timeout zero was rejected.
package stack
