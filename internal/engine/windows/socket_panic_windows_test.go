//go:build windows && netswitch_handlecheck

package winengine

import (
	"fmt"
	"net"
	"strings"
	"testing"
)

func TestSocketHandleTracePanicCapture(t *testing.T) {
	if !startSocketDiagnostics(t) {
		t.Skip("opt in to hosted OS tracing")
	}
	_, socket := pollLifetimePair(t)
	historical := socket.handle.Handle("panic capture control native identity")
	if err := socket.Close(); err != nil {
		t.Fatal(err)
	}
	// Model a wrapper whose raw generation ended outside its own close path.
	// No later operation may reach Windows using the ended value.
	socket.mu.Lock()
	socket.closed = false
	socket.mu.Unlock()
	evidence := &socketEvidence{t: t, tcp: socket,
		local: socket.local.(*net.TCPAddr).AddrPort(), peer: socket.remote.(*net.TCPAddr).AddrPort(),
		handles: []socketTraceHandle{{"ended-native-control", historical}}}
	defer socketFirstFailure.Store(false)
	var caught any
	func() {
		defer func() { caught = recover() }()
		defer evidence.closeTCP()
		socket.handle.Handle("deliberate ended generation for capture control")
	}()
	if caught == nil || !strings.Contains(fmt.Sprint(caught), "deliberate ended generation for capture control") {
		t.Fatalf("diagnostic cleanup lost the original panic: %v", caught)
	}
	if !evidence.failed || evidence.capturedHistory == 0 {
		t.Fatal("panic escaped without its OS handle history")
	}
	t.Log("SOCKET PANIC CONTROL PASS: original tripwire panic preserved, OS history captured before cleanup, no ended-generation I/O")
}
