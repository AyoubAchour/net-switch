package lifecycle_test

import (
	"errors"
	"testing"
)

func heldStoreClient(string) error { return errors.New("Windows only") }
func blockedStoreInstallation(t *testing.T, _, _ string, _ actor) {
	t.Skip("Windows held-directory fallback")
}
