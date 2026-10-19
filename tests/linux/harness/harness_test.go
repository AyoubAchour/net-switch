package harness

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestDecide(t *testing.T) {
	cases := []struct {
		label      Label
		kind       EngineKind
		harnessErr bool
		tally      Tally
		want       Outcome
	}{
		{Parity, Baseline, false, Tally{Checks: 3}, Pass},
		{Parity, Baseline, false, Tally{Checks: 3, Failed: 1}, Fail},
		{Parity, V1, false, Tally{Checks: 3, Failed: 1}, Fail},
		{Parity, Baseline, true, Tally{Checks: 3}, Error},
		{Parity, Baseline, false, Tally{}, Error},
		{Parity, Baseline, false, Tally{Checks: 1, Expects: 1}, Error},
		// The defect reproduces and every mandatory check passes.
		{BaselineDefect, Baseline, false, Tally{Checks: 2, Expects: 1, ExpectFailed: 1}, KnownDefect},
		// A failed prerequisite or invariant is never waived.
		{BaselineDefect, Baseline, false, Tally{Checks: 2, Failed: 1, Expects: 1, ExpectFailed: 1}, Fail},
		{BaselineDefect, Baseline, false, Tally{Checks: 2, Failed: 1}, Fail},
		{BaselineDefect, Baseline, false, Tally{Checks: 2, Expects: 1}, NotReproduced},
		{BaselineDefect, Baseline, false, Tally{Checks: 2}, Error},
		{BaselineDefect, Baseline, false, Tally{Expects: 2, ExpectFailed: 2}, Error},
		{BaselineDefect, Baseline, true, Tally{Expects: 1, ExpectFailed: 1}, Error},
		{BaselineDefect, V1, false, Tally{Checks: 2, Expects: 1}, Pass},
		{BaselineDefect, V1, false, Tally{Checks: 2, Expects: 1, ExpectFailed: 1}, Fail},
		{Requires10, Baseline, false, Tally{}, NotRun},
		{Requires10, Baseline, true, Tally{}, NotRun},
		{Requires10, V1, false, Tally{Checks: 1}, Pass},
		{Requires10, V1, false, Tally{}, Error},
		{Requires10, V1, false, Tally{Checks: 1, Failed: 1}, Fail},
	}
	for _, c := range cases {
		got, _ := Decide(c.label, c.kind, c.harnessErr, c.tally)
		if got != c.want {
			t.Errorf("Decide(%s, %s, err=%v, %+v) = %s, want %s", c.label, c.kind, c.harnessErr, c.tally, got, c.want)
		}
	}
	for _, o := range []Outcome{Fail, NotReproduced, Error} {
		if !o.FailsJob() {
			t.Errorf("%s must fail the job", o)
		}
	}
	for _, o := range []Outcome{Pass, KnownDefect, NotRun} {
		if o.FailsJob() {
			t.Errorf("%s must not fail the job", o)
		}
	}
}

func TestValidate(t *testing.T) {
	ok := func(*T) {}
	good := []*Case{
		{ID: "a.b-c", Title: "x", Label: Parity, Run: ok},
		{ID: "d", Title: "x", Label: BaselineDefect, Defect: "the freeze", Run: ok},
	}
	if err := Validate(good); err != nil {
		t.Fatal(err)
	}
	bad := [][]*Case{
		{{ID: "A", Title: "x", Label: Parity, Run: ok}},
		{{ID: "a", Title: "x", Label: "flaky", Run: ok}},
		{{ID: "a", Title: "x", Label: Parity, Run: ok}, {ID: "a", Title: "y", Label: Parity, Run: ok}},
		{{ID: "a", Label: Parity, Run: ok}},
		{{ID: "a", Title: "x", Label: BaselineDefect, Run: ok}},
		{{ID: "a", Title: "x", Label: Parity, Defect: "named", Run: ok}},
	}
	for i, cases := range bad {
		if Validate(cases) == nil {
			t.Errorf("set %d should be rejected", i)
		}
	}
}

func run(t *testing.T, kind EngineKind, cases ...*Case) *Report {
	t.Helper()
	dir := t.TempDir()
	report := Run(context.Background(), cases, NewReport(), Options{Kind: kind, OutDir: dir, Console: io.Discard})
	if err := report.WriteFiles(dir); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(dir, "report.json"))
	if err != nil {
		t.Fatal(err)
	}
	var back Report
	if err := json.Unmarshal(data, &back); err != nil {
		t.Fatalf("report.json doesn't read back: %v", err)
	}
	return report
}

func outcomes(r *Report) map[string]Outcome {
	m := map[string]Outcome{}
	for _, c := range r.Cases {
		m[c.ID] = c.Outcome
	}
	return m
}

func defect(id string, run func(*T)) *Case {
	return &Case{ID: id, Title: id, Label: BaselineDefect, Defect: "a known defect", Run: run}
}

func TestRunOutcomes(t *testing.T) {
	var order []string
	cases := []*Case{
		{ID: "pass", Title: "p", Label: Parity, Run: func(t *T) { t.Check(true, "fine") }},
		{ID: "fail", Title: "f", Label: Parity, Run: func(t *T) {
			t.Require(false, "stops here")
			t.Check(true, "never reached")
		}},
		defect("reproduced", func(t *T) {
			t.Require(true, "the stream was up first")
			t.Expect(false, "the 60 s freeze")
			t.Check(true, "the other lines were fine")
		}),
		// The review's case: a prerequisite fails before the defect assertion.
		defect("prerequisite-failed", func(t *T) {
			t.Require(false, "bravo's first stream never used line b")
			t.Expect(false, "never reached")
		}),
		defect("unrelated-failure", func(t *T) {
			t.Expect(false, "the defect")
			t.Check(false, "an invariant broke too")
		}),
		defect("undetected", func(t *T) { t.Expect(true, "no freeze seen") }),
		defect("two-assertions", func(t *T) { t.Expect(false, "one"); t.Expect(false, "two") }),
		defect("no-assertion", func(t *T) { t.Check(true, "only a prerequisite") }),
		{ID: "parity-expect", Title: "x", Label: Parity, Run: func(t *T) { t.Expect(false, "not allowed here") }},
		{ID: "later", Title: "l", Label: Requires10, Run: func(t *T) { panic("must not run on the baseline") }},
		defect("broken", func(t *T) {
			t.Expect(false, "looks like the defect")
			t.Fatalf("but the namespace never came up")
		}),
		{ID: "panics", Title: "x", Label: Parity, Run: func(t *T) { panic("boom") }},
		{ID: "empty", Title: "e", Label: Parity, Run: func(t *T) {}},
		{ID: "cleanups", Title: "c", Label: Parity, Run: func(t *T) {
			t.Cleanup(func() { order = append(order, "first") })
			t.Cleanup(func() { order = append(order, "second"); t.Fatalf("cleanup trouble") })
			t.Check(true, "ran")
		}},
	}
	report := run(t, Baseline, cases...)
	want := map[string]Outcome{
		"pass": Pass, "fail": Fail, "reproduced": KnownDefect, "prerequisite-failed": Fail,
		"unrelated-failure": Fail, "undetected": NotReproduced, "two-assertions": Error,
		"no-assertion": Error, "parity-expect": Error, "later": NotRun, "broken": Error,
		"panics": Error, "empty": Error, "cleanups": Error,
	}
	got := outcomes(report)
	for id, o := range want {
		if got[id] != o {
			t.Errorf("%s: got %s, want %s", id, got[id], o)
		}
	}
	if strings.Join(order, ",") != "second,first" {
		t.Errorf("cleanups ran as %v, want last registered first", order)
	}
	if !report.JobFailed {
		t.Error("a run with failures must fail the job")
	}
	for _, c := range report.Cases {
		if c.ID == "fail" && len(c.Checks) != 1 {
			t.Errorf("Require must stop the case; got %d checks", len(c.Checks))
		}
		if c.ID == "prerequisite-failed" && c.Detail() != "bravo's first stream never used line b" {
			t.Errorf("the failed prerequisite must be the reported detail, got %q", c.Detail())
		}
	}
}

func TestBaselineDefectsKeepJobGreen(t *testing.T) {
	report := run(t, Baseline,
		&Case{ID: "p", Title: "p", Label: Parity, Run: func(t *T) { t.Check(true, "ok") }},
		defect("d", func(t *T) { t.Check(true, "prerequisite"); t.Expect(false, "defect") }),
		&Case{ID: "r", Title: "r", Label: Requires10, Run: func(t *T) {}},
	)
	if report.JobFailed {
		t.Fatalf("parity passes, a reproduced defect and a 1.0-only case must leave the job green: %+v", report.Totals)
	}
	v1 := run(t, V1, defect("d", func(t *T) { t.Check(true, "prerequisite"); t.Expect(false, "defect") }))
	if !v1.JobFailed {
		t.Fatal("a baseline defect must fail the job on 1.0")
	}
}

func TestTimeout(t *testing.T) {
	report := run(t, Baseline, &Case{ID: "slow", Title: "s", Label: Parity, Timeout: 50 * time.Millisecond, Run: func(t *T) {
		t.Check(true, "started")
		<-t.Context().Done()
	}})
	if got := report.Cases[0].Outcome; got != Error || !strings.Contains(report.Cases[0].Error, "timed out") {
		t.Fatalf("got %s (%s), want a timeout error", got, report.Cases[0].Error)
	}
	if len(report.Problems) != 0 {
		t.Fatal("a case that stops when it times out mustn't abort the run")
	}
}

func TestStuckCaseAbortsRun(t *testing.T) {
	grace, cleanup := timeoutGrace, cleanupTimeout
	timeoutGrace, cleanupTimeout = 50*time.Millisecond, 50*time.Millisecond
	defer func() { timeoutGrace, cleanupTimeout = grace, cleanup }()
	block := make(chan struct{})
	defer close(block)
	report := run(t, Baseline,
		&Case{ID: "stuck", Title: "s", Label: Parity, Timeout: 20 * time.Millisecond, Run: func(t *T) {
			t.Check(true, "started")
			<-block // ignores its context
		}},
		&Case{ID: "next", Title: "n", Label: Parity, Run: func(t *T) { t.Check(true, "ok") }},
	)
	if len(report.Cases) != 1 || len(report.Problems) == 0 || !report.JobFailed {
		t.Fatalf("a case that won't stop must abort the run: %d cases, problems %v", len(report.Cases), report.Problems)
	}
	stuckCleanup := run(t, Baseline, &Case{ID: "c", Title: "c", Label: Parity, Run: func(t *T) {
		t.Check(true, "ran")
		t.Cleanup(func() { <-block })
	}}, &Case{ID: "next", Title: "n", Label: Parity, Run: func(t *T) { t.Check(true, "ok") }})
	if len(stuckCleanup.Cases) != 1 || stuckCleanup.Cases[0].Outcome != Error || len(stuckCleanup.Problems) == 0 {
		t.Fatalf("a cleanup that won't finish must fail the case and abort the run: %+v", stuckCleanup.Problems)
	}
}

func TestRunProblemFailsJob(t *testing.T) {
	report := NewReport()
	report.Fail("the filter matched no cases")
	if !report.JobFailed {
		t.Fatal("a run problem must fail the job")
	}
	var md strings.Builder
	report.WriteMarkdown(&md)
	if !strings.Contains(md.String(), "filter matched no cases") {
		t.Fatal("run problems must show in the summary")
	}
}
