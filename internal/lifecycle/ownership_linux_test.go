package lifecycle

import "testing"

func TestRuleFingerprintKeepsSelectorsAndAcceptsKernelLifetimeFlags(t *testing.T) {
	want := "9102: from all iif NetSwitch goto 9110"
	for _, line := range []string{
		"9102:\tfrom all iif NetSwitch goto 9110",
		"9102: from all iif NetSwitch [detached] goto 9110",
		"9102: from all iif NetSwitch [detached] goto 9110 [unresolved]",
	} {
		if got := ruleText(line); got != want {
			t.Fatal("legitimate teardown/partial-start state lost ownership", got)
		}
	}
	if ruleText("9102: from all iif another-interface goto 9110") == want {
		t.Fatal("replacement rule matched by priority")
	}
}
