package lifecycle_test

import (
	"strings"
	"testing"
)

const actorComment = "Net Switch lifecycle CI disposable account"

func requireActorName(t *testing.T, name string) {
	t.Helper()
	switch name {
	case "NSLifecycleOwner", "NSLifecycleOther", "NSNativeOther", "NSNativeControlOwner":
	default:
		t.Fatalf("unexpected disposable account name %q", name)
	}
	if !hosted() {
		t.Fatal("disposable accounts require a hosted runner")
	}
}

// Both sudo and sudo-rs print this completed root-side listing when no
// commands match. A mere nonzero exit could instead be a lookup/policy error.
func noSudoCommands(name, output string, exit int) bool {
	message := strings.TrimSpace(output)
	prefix := "User " + name + " is not allowed to run sudo on "
	return (exit == 0 || exit == 1) && strings.HasPrefix(message, prefix) && strings.HasSuffix(message, ".") && len(message) > len(prefix)+1 && !strings.ContainsAny(message, "\r\n")
}

func TestNativeActorSudoListing(t *testing.T) {
	for _, tc := range []struct {
		text  string
		exit  int
		allow bool
	}{
		{"User NSNativeOther is not allowed to run sudo on runner.\n", 0, true},
		{"User NSNativeOther is not allowed to run sudo on runner.\n", 1, true},
		{"User NSNativeOther may run the following commands on runner:\n (ALL) NOPASSWD: ALL", 0, false},
		{"sudo: unable to load policy", 1, false},
		{"User other is not allowed to run sudo on runner.", 0, false},
		{"sudo: policy warning\nUser NSNativeOther is not allowed to run sudo on runner.", 1, false},
	} {
		if noSudoCommands("NSNativeOther", tc.text, tc.exit) != tc.allow {
			t.Fatal(tc)
		}
	}
}
