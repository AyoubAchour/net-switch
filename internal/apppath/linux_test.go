package apppath

import "testing"

func TestLinuxPathIdentity(t *testing.T) {
	if got := Normalize("/opt/Example/1.2.3/App", Linux); got != "/opt/Example/*/App" {
		t.Fatalf("Linux normalized path %q", got)
	}
	if Normalize("/opt/Example/App", Linux) == Normalize("/opt/example/app", Linux) {
		t.Fatal("Linux path identity folded case")
	}
}
