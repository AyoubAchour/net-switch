// Package harness runs labelled acceptance cases and decides, strictly, whether
// a run passed. It knows nothing about networking: the Linux suite supplies the
// cases, and this package records what each one checked and what it means for
// the job.
//
// A case makes two kinds of assertion:
//
//   - Check and Require: mandatory, on every engine. Prerequisites ("the
//     stream was up before the address changed"), invariants ("nothing got
//     past the cap") and every other behaviour the case relies on.
//   - Expect: the one named defect assertion of a baseline-defect case. It's
//     the only assertion that may fail without failing the job, and only on
//     the baseline.
//
// Every case carries one label:
//
//   - parity: must pass on the baseline (today's engine, sing-box) and on 1.0.
//     It may not call Expect.
//   - baseline-defect: a known defect of the baseline, named by the case. It
//     calls Expect exactly once. On the baseline that assertion must fail
//     (the defect reproduces) while every mandatory check passes; the defect
//     is recorded and the job stays green. If the assertion passes, the job
//     fails: a case that can't see the defect proves nothing when it later
//     passes on 1.0. On 1.0 everything must pass.
//   - requires-1.0: needs 1.0's control protocol. Not run on the baseline,
//     and recorded as such; must pass on 1.0.
//
// A harness problem (a namespace that won't come up, a test program that
// crashes, a driver that isn't implemented), a case that checks nothing, or a
// case that breaks these rules fails the job whatever its label.
package harness

import "fmt"

// Label says what a case's result means for each engine.
type Label string

const (
	Parity         Label = "parity"
	BaselineDefect Label = "baseline-defect"
	Requires10     Label = "requires-1.0"
)

// Valid reports whether l is one of the three labels.
func (l Label) Valid() bool {
	return l == Parity || l == BaselineDefect || l == Requires10
}

// EngineKind is what the engine under test is: today's baseline or 1.0.
type EngineKind string

const (
	Baseline EngineKind = "baseline"
	V1       EngineKind = "1.0"
)

// Outcome is a case's recorded result.
type Outcome string

const (
	// Pass: every assertion passed (on the baseline, only for parity cases).
	Pass Outcome = "pass"
	// Fail: a mandatory check failed, or on 1.0 any assertion failed.
	Fail Outcome = "fail"
	// KnownDefect: a baseline-defect case's named defect reproduced on the
	// baseline, and all its mandatory checks passed.
	KnownDefect Outcome = "known-defect"
	// NotReproduced: a baseline-defect case's defect assertion passed on the
	// baseline, so the case can't be trusted to detect the defect.
	NotReproduced Outcome = "defect-not-reproduced"
	// NotRun: a requires-1.0 case on the baseline.
	NotRun Outcome = "not-run"
	// Error: the harness couldn't run the case, or the case broke the rules.
	Error Outcome = "error"
)

// FailsJob reports whether this outcome makes the run fail.
func (o Outcome) FailsJob() bool {
	return o == Fail || o == NotReproduced || o == Error
}

// Tally counts a case's assertions.
type Tally struct {
	Checks, Failed        int // mandatory
	Expects, ExpectFailed int // the defect assertion
}

// Decide turns what happened in a case into its outcome; for Error it also
// says why when the reason isn't a harness error already recorded.
func Decide(label Label, kind EngineKind, harnessErr bool, t Tally) (Outcome, string) {
	switch {
	case label == Requires10 && kind == Baseline:
		return NotRun, ""
	case harnessErr:
		return Error, ""
	case t.Failed > 0:
		// A failed prerequisite or invariant, possibly before the case got to
		// its defect assertion: never waived.
		return Fail, ""
	case label == BaselineDefect && t.Expects != 1:
		return Error, fmt.Sprintf("a baseline-defect case makes exactly one defect assertion (Expect); this one made %d", t.Expects)
	case label != BaselineDefect && t.Expects > 0:
		return Error, "only a baseline-defect case may make a defect assertion (Expect)"
	case t.Checks+t.Expects == 0:
		return Error, "the case made no checks"
	case label == BaselineDefect && kind == Baseline && t.ExpectFailed > 0:
		return KnownDefect, ""
	case label == BaselineDefect && kind == Baseline:
		return NotReproduced, ""
	case t.ExpectFailed > 0:
		return Fail, ""
	}
	return Pass, ""
}

// Explain is a one-line reading of an outcome for logs and the summary.
func Explain(o Outcome) string {
	switch o {
	case Pass:
		return "passed"
	case Fail:
		return "FAILED"
	case KnownDefect:
		return "known baseline defect, reproduced (required to pass on 1.0)"
	case NotReproduced:
		return "FAILED: the baseline defect did not reproduce, so this case can't detect it"
	case NotRun:
		return "not run: needs 1.0's control protocol"
	case Error:
		return "FAILED: the harness could not run this case"
	}
	return fmt.Sprintf("unknown outcome %q", string(o))
}
