//go:build lifecycle_test && !windows

package lifecycle

import "errors"

// Linux has no adapter-loss exit: a failed read pump is an ordinary engine
// failure (exit 1), which Control counts toward its budget.
func nativeProofReadFault() error { return errors.New("hosted TUN read fault") }
