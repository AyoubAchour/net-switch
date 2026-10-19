// Package harness runs labelled acceptance cases and decides, strictly, whether
// a run passed. It knows nothing about networking: the Linux suite supplies the
// cases, and this package records what each one checked and what it means for
// the job.
//
// Every case carries one label:
//
//   - parity: must pass on the baseline (today's engine, sing-box) and on 1.0.
//   - baseline-defect: a known defect of the baseline. On the baseline it must
//     reproduce: the defect is recorded and the job stays green. If it doesn't
//     reproduce, the job fails, because a case that can't see the defect proves
//     nothing when it later passes on 1.0. On 1.0 it must pass.
//   - requires-1.0: needs 1.0's control protocol. Not run on the baseline, and
//     recorded as such; must pass on 1.0.
//
// A case that hits a harness problem (a namespace that won't come up, a test
// program that crashes, a driver that isn't implemented) fails the job whatever
// its label, and so does a case that made no checks at all.
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
	// Pass: every check passed (on the baseline, only for parity cases).
	Pass Outcome = "pass"
	// Fail: a required check failed.
	Fail Outcome = "fail"
	// KnownDefect: a baseline-defect case reproduced its defect on the baseline.
	KnownDefect Outcome = "known-defect"
	// NotReproduced: a baseline-defect case passed on the baseline, so it can't
	// be trusted to detect the defect.
	NotReproduced Outcome = "defect-not-reproduced"
	// NotRun: a requires-1.0 case on the baseline.
	NotRun Outcome = "not-run"
	// Error: the harness couldn't run the case, or the case checked nothing.
	Error Outcome = "error"
)

// FailsJob reports whether this outcome makes the run fail.
func (o Outcome) FailsJob() bool {
	return o == Fail || o == NotReproduced || o == Error
}

// Decide turns what happened in a case into its outcome. harnessErr is set when
// the case couldn't run to a verdict; checks and failed count its behavioural
// checks.
func Decide(label Label, kind EngineKind, harnessErr bool, checks, failed int) Outcome {
	if label == Requires10 && kind == Baseline {
		return NotRun
	}
	if harnessErr || checks == 0 {
		return Error
	}
	defectOnBaseline := label == BaselineDefect && kind == Baseline
	switch {
	case failed > 0 && defectOnBaseline:
		return KnownDefect
	case failed > 0:
		return Fail
	case defectOnBaseline:
		return NotReproduced
	default:
		return Pass
	}
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
