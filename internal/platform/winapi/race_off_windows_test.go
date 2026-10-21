//go:build windows && !race

package winapi

// raceEnabled reports whether this test binary has the race detector.
const raceEnabled = false
