package lifecycle_test

import "testing"

const actorComment = "Net Switch lifecycle CI disposable account"

func requireActorName(t *testing.T, name string) {
	t.Helper()
	switch name {
	case "NSLifecycleOwner", "NSLifecycleOther", "NSNativeOther":
	default:
		t.Fatalf("unexpected disposable account name %q", name)
	}
	if !hosted() {
		t.Fatal("disposable accounts require a hosted runner")
	}
}
