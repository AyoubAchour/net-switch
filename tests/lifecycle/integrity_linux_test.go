package lifecycle_test

import (
	"errors"
	"testing"
)

func lowPipeClient() error { return errors.New("Windows only") }
func lowIntegrityCapacity(t *testing.T, _ actor) {
	t.Skip("Linux uses the owner UID and a separate private socket, not Windows integrity levels")
}
