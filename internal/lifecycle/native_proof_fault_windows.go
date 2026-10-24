//go:build lifecycle_test && windows

package lifecycle

import (
	"errors"

	"github.com/AyoubAchour/net-switch/internal/wintun"
)

// nativeProofReadFault is the error the real Wintun session reports when the
// adapter is removed under the engine. The engine's own loss handler turns it
// into the clean exit 3 Control must restart without counting.
func nativeProofReadFault() error {
	return errors.Join(wintun.ErrAdapterRemoved, errors.New("hosted adapter-removed fault"))
}
