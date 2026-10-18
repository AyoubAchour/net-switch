package main

import "testing"

func TestLinuxModesAreNotSupportedYet(t *testing.T) {
	for _, mode := range []string{"meters", "outside", "network", "probe", "policy", "run"} {
		if code := runOptions(options{mode: mode}); code != 1 {
			t.Errorf("%s returned %d, want unsupported exit code 1", mode, code)
		}
	}
}
