package harness

import (
	"strings"
	"testing"
)

func TestReleaseBlockerRetainsBothPassingAndFailingMeasurements(t *testing.T) {
	for _, measured := range []bool{false, true} {
		c := &Case{ID: "storm", Title: "storm", Label: Parity, ReleaseBlocker: "eBPF follow-up recorded in the spec", Run: func(t *T) {
			t.Check(true, "capacity still holds")
			t.ReleaseCheck(measured, "the unchanged attribution threshold: %t", measured)
		}}
		r := run(t, V1, c)
		if r.JobFailed || r.Cases[0].Outcome != ReleaseBlocked || r.Cases[0].Checks[1].OK != measured || !r.Cases[0].Checks[1].ReleaseBlocker {
			t.Fatalf("PR result hid or changed its release measurement: %+v", r)
		}
		if err := CheckRelease([]*Case{c}); err == nil || !strings.Contains(err.Error(), "storm: release-blocker") {
			t.Fatalf("one measured pass cleared a declared release blocker: %v", err)
		}
	}
}

func TestReleaseBlockerCannotWaiveOtherFailures(t *testing.T) {
	for _, expect := range []bool{false, true} {
		c := &Case{ID: "storm", Title: "storm", Label: Parity, ReleaseBlocker: "eBPF follow-up"}
		if expect {
			c.Label, c.Defect = BaselineDefect, "baseline defect"
		}
		c.Run = func(t *T) {
			t.Check(expect, "mandatory capacity assertion")
			if expect {
				t.Expect(false, "mandatory 1.0 behaviour")
			}
			t.ReleaseCheck(false, "attribution threshold still failed")
		}
		r := run(t, V1, c)
		if !r.JobFailed || r.Cases[0].Outcome != Fail || strings.Contains(r.Cases[0].Detail(), "attribution") {
			t.Fatalf("release classification hid a mandatory failure: %+v", r.Cases[0])
		}
	}
}

func TestReleaseBlockerMustBeDeclaredAndActuallyMeasured(t *testing.T) {
	r := run(t, V1, &Case{ID: "storm", Title: "storm", Label: Parity, ReleaseBlocker: "eBPF follow-up", Run: func(t *T) {
		t.Check(true, "ordinary assertion")
	}})
	if !r.JobFailed || r.Cases[0].Outcome != Error {
		t.Fatalf("unmeasured declared gate passed: %+v", r.Cases[0])
	}
	r = run(t, V1, &Case{ID: "undeclared", Title: "undeclared", Label: Parity, Run: func(t *T) { t.ReleaseCheck(false, "cannot waive this") }})
	if !r.JobFailed || r.Cases[0].Outcome != Error {
		t.Fatal("an undeclared release check waived a failure")
	}
}

func TestEveryReleaseMeasurementRemainsVisible(t *testing.T) {
	r := run(t, V1, &Case{ID: "load", Title: "load", Label: Parity, ReleaseBlocker: "eBPF follow-up", Run: func(t *T) {
		t.Check(true, "routing is correct")
		t.ReleaseCheck(true, "stream owner found")
		t.ReleaseCheck(false, "eleven of eighty-six lookups missed")
	}})
	if r.JobFailed || r.Cases[0].Outcome != ReleaseBlocked || len(r.Cases[0].Checks) != 3 {
		t.Fatalf("multiple attribution measurements were lost: %+v", r)
	}
	detail := r.Cases[0].Detail()
	if !strings.Contains(detail, "threshold met: stream owner found") || !strings.Contains(detail, "threshold failed: eleven of eighty-six lookups missed") {
		t.Fatalf("a passing first measurement hid the later failure: %s", detail)
	}
}

func TestReleaseGateIncludesPendingAndRejectsEmptyCatalogues(t *testing.T) {
	if CheckRelease(nil) == nil {
		t.Fatal("an empty or filtered-away catalogue passed the release gate")
	}
	c := &Case{ID: "future", Title: "future gate", Label: Pending, Waits: "a required fixture"}
	if err := CheckRelease([]*Case{c}); err == nil || !strings.Contains(err.Error(), "future: pending") {
		t.Fatalf("pending gate was not a release failure: %v", err)
	}
	ready := &Case{ID: "ready", Title: "implemented", Label: Parity, Run: func(t *T) { t.Check(true, "implemented") }}
	if err := CheckRelease([]*Case{ready}); err != nil {
		t.Fatalf("catalogue with no pending or deferred gates: %v", err)
	}
}
