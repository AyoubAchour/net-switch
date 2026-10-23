package lifecycle_test

import (
	"net"
	"testing"
	"time"
)

var nativeMeasurementEpoch = time.Now()

func nativeMeasurementNow() time.Duration { return time.Since(nativeMeasurementEpoch) }

func nativeSocketObserver(t *testing.T, conn net.Conn) nativeSocketObservation {
	t.Helper()
	// The existing Linux fixture returns a Unix relay connection. Do not
	// mislabel its local read deadlines as the namespace TCP socket's timers.
	t.Logf("M4_TCP client=%T native_tcp_options=unavailable (namespace relay)", conn)
	// An EOF from this relay cannot prove whether the peer reset or the real
	// TCP client timed out. Keep it a failure rather than guessing its cause.
	return nativeSocketObservation{sample: func(string) {}}
}
