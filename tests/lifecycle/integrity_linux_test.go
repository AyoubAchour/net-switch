package lifecycle_test

import (
	"errors"
	"testing"
)

func lowPipeClient() error  { return errors.New("Windows only") }
func mediumPipeRead() error { return errors.New("Windows only") }
func lowIntegrityPairing(t *testing.T, _ *client, _ actor) {
	t.Skip("Linux has no integrity levels; TCP identity is the socket's owning UID")
}
func lowIntegrityCapacity(t *testing.T, _ actor) {
	t.Skip("Linux uses the owner UID and a separate private socket, not Windows integrity levels")
}
