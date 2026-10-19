package buildinfo

import "testing"

func TestStringFallsBackToDev(t *testing.T) {
	saved := Version
	defer func() { Version = saved }()

	Version = ""
	if got := String(); got != "dev" {
		t.Fatalf("String() = %q, want dev", got)
	}
	Version = "1.0.0"
	if got := String(); got != "1.0.0" {
		t.Fatalf("String() = %q, want 1.0.0", got)
	}
}
