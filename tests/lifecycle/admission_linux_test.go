package lifecycle_test

import (
	"errors"
	"testing"
)

// The idle-open admission DoS is Windows-specific: it turns on the named-pipe
// zero-access open and the pre-authentication read. Linux's private owner
// socket is separate from its public status/activation socket.
func idleAdmissionFlood() error {
	return errors.New("admission flood is a Windows-only probe")
}

func idleAdmissionCapacity(t *testing.T, _, _ string, _, _ actor) {
	t.Skip("idle-open admission DoS is Windows-specific")
}
