//go:build windows && !wintun_boundaries

package wintun

const wordBoundaryHooksEnabled = false

func nextWordReadBatch() uint64                       { return 0 }
func observeWordRingRead([]byte, uint32, uint64, int) {}

type wordBoundaryBatch struct{}

func newWordBoundaryBatch() wordBoundaryBatch      { return wordBoundaryBatch{} }
func (*wordBoundaryBatch) add([]byte, uint32, int) {}
func (*wordBoundaryBatch) publish()                {}
