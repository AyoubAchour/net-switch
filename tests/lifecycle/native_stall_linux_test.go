package lifecycle_test

import (
	"net"
	"testing"
)

func nativeSocketObserver(t *testing.T, conn net.Conn) func(string) {
	t.Helper()
	// The existing Linux fixture returns a Unix relay connection. Do not
	// mislabel its local read deadlines as the namespace TCP socket's timers.
	t.Logf("M4_TCP client=%T native_tcp_options=unavailable (namespace relay)", conn)
	return func(string) {}
}
