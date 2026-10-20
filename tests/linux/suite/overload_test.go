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
	// A 200 ms recovery in the middle of the old 3.5 s offer leaves neither
	// side with 2 s of steady demand. A longer offer can meet the very same
	// precondition, while the first-3.5-second verdict must still say failure.
	longer := make([]int64, 100)
	for i := range longer {
		if i < 32 || i >= 36 {
			longer[i] = 2 * mib
		}
	}
	if old, offered := steadyMS(longer[:70], 50, 4, earnPerWindow), steadyMS(longer, 50, 4, earnPerWindow); old >= earnSteadyMS || offered < earnSteadyMS {
		t.Fatalf("old and offered demand verdicts collapsed: %d / %d ms", old, offered)
	}
}
