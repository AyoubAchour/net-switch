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
		label         Label
		kind          EngineKind
		harnessErr    bool
		checks, fails int
		want          Outcome
	}{
		{Parity, Baseline, false, 3, 0, Pass},
		{Parity, Baseline, false, 3, 1, Fail},
		{Parity, V1, false, 3, 1, Fail},
		{Parity, Baseline, true, 3, 0, Error},
		{Parity, Baseline, false, 0, 0, Error},
		{BaselineDefect, Baseline, false, 2, 1, KnownDefect},
		{BaselineDefect, Baseline, false, 2, 0, NotReproduced},
		{BaselineDefect, Baseline, true, 2, 1, Error},
		{BaselineDefect, V1, false, 2, 0, Pass},
		{BaselineDefect, V1, false, 2, 1, Fail},
		{Requires10, Baseline, false, 0, 0, NotRun},
		{Requires10, Baseline, true, 0, 0, NotRun},
		{Requires10, V1, false, 1, 0, Pass},
		{Requires10, V1, false, 0, 0, Error},
		{Requires10, V1, false, 1, 1, Fail},
	}
	for _, c := range cases {
		got := Decide(c.label, c.kind, c.harnessErr, c.checks, c.fails)
		if got != c.want {
			t.Errorf("Decide(%s, %s, err=%v, %d checks, %d failed) = %s, want %s", c.label, c.kind, c.harnessErr, c.checks, c.fails, got, c.want)
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
	if err := Validate([]*Case{{ID: "a.b-c", Title: "x", Label: Parity, Run: ok}}); err != nil {
		t.Fatal(err)
	}
	bad := [][]*Case{
		{{ID: "A", Title: "x", Label: Parity, Run: ok}},
		{{ID: "a", Title: "x", Label: "flaky", Run: ok}},
		{{ID: "a", Title: "x", Label: Parity, Run: ok}, {ID: "a", Title: "y", Label: Parity, Run: ok}},
		{{ID: "a", Label: Parity, Run: ok}},
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

func TestRunOutcomes(t *testing.T) {
	var order []string
	cases := []*Case{
		{ID: "pass", Title: "p", Label: Parity, Run: func(t *T) { t.Check(true, "fine") }},
		{ID: "fail", Title: "f", Label: Parity, Run: func(t *T) {
			t.Require(false, "stops here")
			t.Check(true, "never reached")
		}},
		{ID: "defect", Title: "d", Label: BaselineDefect, Run: func(t *T) { t.Check(false, "the 60 s freeze") }},
		{ID: "undetected", Title: "u", Label: BaselineDefect, Run: func(t *T) { t.Check(true, "no freeze seen") }},
		{ID: "later", Title: "l", Label: Requires10, Run: func(t *T) { panic("must not run on the baseline") }},
		{ID: "broken", Title: "b", Label: BaselineDefect, Run: func(t *T) {
			t.Check(false, "looks like the defect")
			t.Fatalf("but the namespace never came up")
		}},
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
		"pass": Pass, "fail": Fail, "defect": KnownDefect, "undetected": NotReproduced,
		"later": NotRun, "broken": Error, "panics": Error, "empty": Error, "cleanups": Error,
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
	}
}

func TestBaselineDefectsKeepJobGreen(t *testing.T) {
	report := run(t, Baseline,
		&Case{ID: "p", Title: "p", Label: Parity, Run: func(t *T) { t.Check(true, "ok") }},
		&Case{ID: "d", Title: "d", Label: BaselineDefect, Run: func(t *T) { t.Check(false, "defect") }},
		&Case{ID: "r", Title: "r", Label: Requires10, Run: func(t *T) {}},
	)
	if report.JobFailed {
		t.Fatalf("parity passes, a reproduced defect and a 1.0-only case must leave the job green: %+v", report.Totals)
	}
	v1 := run(t, V1, &Case{ID: "d", Title: "d", Label: BaselineDefect, Run: func(t *T) { t.Check(false, "defect") }})
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
