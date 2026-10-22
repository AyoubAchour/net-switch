//go:build windows && !wintun_integrity

package wintun

const integrityHooksEnabled = false

// Inlined away in normal builds: no callback, state, or per-packet branch.
func observeRingReceive(_, _ []byte) {}
func observeRingSend(_, _ []byte)    {}

type integrityRingBatch struct{}

func (*integrityRingBatch) add(_, _ []byte) {}
func (*integrityRingBatch) publish()        {}
