package lifecycle_test

import (
	"errors"
	"testing"
)

// The idle-open admission DoS is Windows-specific: it turns on the named-pipe
// zero-access open and the shared public status pipe. The Linux owner socket
// is reachable only by root and the enrolled UID, so there is no public
// endpoint for another user to flood.
func idleAdmissionFlood() error {
	return errors.New("admission flood is a Windows-only probe")
}

func idleAdmissionCapacity(t *testing.T, _, _ string, _, _ actor) {
	t.Skip("idle-open admission DoS is Windows-specific")
}
