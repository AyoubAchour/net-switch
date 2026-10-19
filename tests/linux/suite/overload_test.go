//go:build linux

package suite

import "testing"

func TestSteadyMS(t *testing.T) {
	const mib = 1 << 20
	even := make([]int64, 40) // 2 s of 50 ms bins, 2 MiB each: 8 MiB in any four
	for i := range even {
		even[i] = 2 * mib
	}
	if got := steadyMS(even, 50, earnWindowBins, earnPerWindow); got != 2000 {
		t.Errorf("2 s of steady demand reads %d ms, want 2000", got)
	}
	// The same bytes on average, but a quiet patch in the middle: no stretch
	// is steady for 2 s, so it can't count as earning the buffer.
	uneven := append([]int64{}, even...)
	for i := 18; i < 22; i++ {
		uneven[i] = 0
	}
	uneven[0], uneven[39] = 6*mib, 6*mib
	if got := steadyMS(uneven, 50, earnWindowBins, earnPerWindow); got >= earnSteadyMS {
		t.Errorf("demand with a 200 ms gap reads %d ms steady, want under %d", got, earnSteadyMS)
	}
	if got := steadyMS(nil, 50, earnWindowBins, earnPerWindow); got != 0 {
		t.Errorf("no bins read %d ms", got)
	}
}
