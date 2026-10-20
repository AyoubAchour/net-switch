package harness

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"time"
)

// DefaultTimeout bounds a case that doesn't set its own.
const DefaultTimeout = 120 * time.Second

// After a case times out, it gets this long to notice before the run gives up
// on it; each cleanup gets cleanupTimeout. Variables so tests can shorten them.
var (
	timeoutGrace   = 15 * time.Second
	cleanupTimeout = 90 * time.Second
)

// Case is one acceptance case.
type Case struct {
	ID    string // stable, dotted: "udp.stun-same-mapping"
	Title string
	Label Label
	// Defect names the known baseline defect a baseline-defect case's one
	// Expect assertion checks for. Only baseline-defect cases have one.
	Defect string
	// ReleaseBlocker names the recorded design decision deferring the case's
	// ReleaseChecks. Every ordinary Check and Expect remains mandatory on 1.0.
	ReleaseBlocker string
	// Waits says what a pending gate needs before it can be checked. Only
	// pending cases have one, and they have no Run.
	Waits   string
	Spec    string // the SYSTEM-DESIGN.md sections it checks, e.g. "5.3"
	Timeout time.Duration
	Run     func(t *T)
}

var idPattern = regexp.MustCompile(`^[a-z0-9]+(?:[.-][a-z0-9]+)*$`)

// Validate catches cases that would make a report ambiguous.
func Validate(cases []*Case) error {
	seen := map[string]bool{}
	for _, c := range cases {
		switch {
		case !idPattern.MatchString(c.ID):
			return fmt.Errorf("case id %q isn't lower-case dotted words", c.ID)
		case seen[c.ID]:
			return fmt.Errorf("case id %q is used twice", c.ID)
		case !c.Label.Valid():
			return fmt.Errorf("case %s has no valid label (%q)", c.ID, c.Label)
		case c.Title == "":
			return fmt.Errorf("case %s needs a title", c.ID)
		case c.Label == Pending && (c.Waits == "" || c.Run != nil):
			return fmt.Errorf("pending case %s must say what it waits for and have no Run function", c.ID)
		case c.Label == Pending && c.ReleaseBlocker != "":
			return fmt.Errorf("pending case %s cannot also declare an executable release check", c.ID)
		case c.Label != Pending && c.Run == nil:
			return fmt.Errorf("case %s needs a Run function", c.ID)
		case c.Label != Pending && c.Waits != "":
			return fmt.Errorf("case %s says what it waits for but isn't labelled pending", c.ID)
		case c.Label == BaselineDefect && c.Defect == "":
			return fmt.Errorf("baseline-defect case %s must name its defect", c.ID)
		case c.Label != BaselineDefect && c.Defect != "":
			return fmt.Errorf("case %s names a defect but isn't labelled baseline-defect", c.ID)
		}
		seen[c.ID] = true
	}
	return nil
}

// Check is one assertion a case made.
type Check struct {
	OK      bool   `json:"ok"`
	Message string `json:"message"`
	// Defect marks the baseline-defect case's one Expect assertion.
	Defect         bool `json:"defect,omitempty"`
	ReleaseBlocker bool `json:"releaseBlocker,omitempty"`
}

// T is a running case. Like testing.T, Require and Fatalf stop the case and
// must be called from the case's own goroutine.
type T struct {
	ctx     context.Context
	kind    EngineKind
	c       *Case
	dir     string
	console io.Writer
	log     *os.File

	mu         sync.Mutex
	checks     []Check
	notes      []string
	harnessErr string
	cleanups   []func()
}

// Context is cancelled when the case times out.
func (t *T) Context() context.Context {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.ctx
}

// Kind is the kind of engine under test.
func (t *T) Kind() EngineKind { return t.kind }

// ID is the case's id.
func (t *T) ID() string { return t.c.ID }

// Dir is the case's own folder for logs and files; it's uploaded with the report.
func (t *T) Dir() string { return t.dir }

func (t *T) write(prefix, text string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	stamp := time.Now().UTC().Format("15:04:05.000")
	for _, line := range strings.Split(strings.TrimRight(text, "\n"), "\n") {
		fmt.Fprintf(t.console, "    %-6s %s\n", prefix, line)
		if t.log != nil {
			fmt.Fprintf(t.log, "%s %-6s %s\n", stamp, prefix, line)
		}
	}
}

// Logf records detail in the case log and the console.
func (t *T) Logf(format string, args ...any) { t.write("", fmt.Sprintf(format, args...)) }

// Note records a measurement; notes also go in the report.
func (t *T) Note(format string, args ...any) {
	text := fmt.Sprintf(format, args...)
	t.mu.Lock()
	t.notes = append(t.notes, text)
	t.mu.Unlock()
	t.write("note", text)
}

// Check records a mandatory assertion and reports whether it passed. A failed
// check fails the case on every engine and under every label.
func (t *T) Check(ok bool, format string, args ...any) bool {
	text := fmt.Sprintf(format, args...)
	t.mu.Lock()
	t.checks = append(t.checks, Check{OK: ok, Message: text})
	t.mu.Unlock()
	if ok {
		t.write("ok", text)
	} else {
		t.write("FAIL", text)
	}
	return ok
}

// ReleaseCheck retains the exact assertion and measurement for a declared
// release requirement. It cannot waive a prerequisite or an ordinary Check.
func (t *T) ReleaseCheck(ok bool, format string, args ...any) bool {
	if t.c.ReleaseBlocker == "" || t.kind != V1 {
		t.markError("release check used without a declared 1.0 release blocker")
		return false
	}
	text := fmt.Sprintf(format, args...)
	t.mu.Lock()
	t.checks = append(t.checks, Check{OK: ok, Message: text, ReleaseBlocker: true})
	t.mu.Unlock()
	result := "threshold FAILED"
	if ok {
		result = "threshold met"
	}
	t.write("blocker", result+": "+text)
	return ok
}

// Require is Check, and stops the case when the check fails. Use it for
// prerequisites the rest of the case depends on.
func (t *T) Require(ok bool, format string, args ...any) {
	if !t.Check(ok, format, args...) {
		runtime.Goexit()
	}
}

// Expect is a baseline-defect case's one defect assertion: what 1.0 must do
// and the baseline is known not to. It doesn't stop the case, so mandatory
// checks after it still run.
func (t *T) Expect(ok bool, format string, args ...any) bool {
	text := fmt.Sprintf(format, args...)
	t.mu.Lock()
	t.checks = append(t.checks, Check{OK: ok, Message: text, Defect: true})
	t.mu.Unlock()
	switch {
	case ok:
		t.write("ok", text)
	case t.kind == Baseline && t.c.Label == BaselineDefect:
		t.write("defect", text)
	default:
		t.write("FAIL", text)
	}
	return ok
}

// Fatalf records that the harness couldn't do its job and stops the case. It
// fails the run whatever the case's label.
func (t *T) Fatalf(format string, args ...any) {
	t.markError(fmt.Sprintf(format, args...))
	runtime.Goexit()
}

// Cleanup registers fn to run after the case, last registered first, even when
// the case fails or times out. A cleanup may call Check or Logf; its Fatalf
// records a harness error and ends only that cleanup.
func (t *T) Cleanup(fn func()) {
	t.mu.Lock()
	t.cleanups = append(t.cleanups, fn)
	t.mu.Unlock()
}

func (t *T) markError(text string) {
	t.mu.Lock()
	if t.harnessErr == "" {
		t.harnessErr = text
	}
	t.mu.Unlock()
	t.write("ERROR", text)
}

// Options control a run.
type Options struct {
	Kind    EngineKind
	OutDir  string
	Console io.Writer
	// Before and After wrap every case that runs (for example to build and tear
	// down the network). After runs even when the case fails or times out.
	Before func(t *T)
	After  func(t *T)
	// GitHub makes failures and known defects show as annotations in Actions.
	GitHub bool
	// Progress is called with the report after each case, so a run cut short
	// still leaves one behind.
	Progress func(*Report)
}

// Run runs the cases in order and returns the report. A case or cleanup that
// won't stop aborts the run: whatever it's still doing would corrupt the next
// case.
func Run(ctx context.Context, cases []*Case, report *Report, opts Options) *Report {
	if opts.Console == nil {
		opts.Console = os.Stdout
	}
	report.Kind = opts.Kind
	for i, c := range cases {
		result, stuck := runCase(ctx, c, opts)
		report.Cases = append(report.Cases, result)
		if stuck != "" {
			report.Fail("run aborted after %s, with %d cases not run: %s", c.ID, len(cases)-i-1, stuck)
		}
		report.finish()
		if opts.Progress != nil {
			opts.Progress(report)
		}
		if stuck != "" || ctx.Err() != nil {
			break
		}
	}
	report.finish()
	return report
}

func runCase(parent context.Context, c *Case, opts Options) (CaseResult, string) {
	result := CaseResult{ID: c.ID, Title: c.Title, Label: c.Label, Defect: c.Defect, Waits: c.Waits, Spec: c.Spec, ReleaseBlocker: c.ReleaseBlocker}
	console := opts.Console
	if c.Label == Requires10 && opts.Kind == Baseline {
		result.Outcome = NotRun
		fmt.Fprintf(console, "--- SKIP   %s [%s] %s: %s\n", c.ID, c.Label, c.Title, Explain(NotRun))
		return result, ""
	}
	if c.Label == Pending {
		result.Outcome, _ = Decide(c.Label, opts.Kind, false, Tally{})
		verb := map[Outcome]string{PendingGate: "PENDING", GateMissing: "FAIL"}[result.Outcome]
		fmt.Fprintf(console, "--- %-6s %s [%s] %s: %s\n           waits for: %s\n", verb, c.ID, c.Label, c.Title, Explain(result.Outcome), c.Waits)
		if opts.GitHub {
			kind := "notice"
			if result.Outcome.FailsJob() {
				kind = "error"
			}
			fmt.Fprintf(console, "::%s title=%s::%s: waits for %s\n", kind, annotationEscape(c.ID), annotationEscape(Explain(result.Outcome)), annotationEscape(c.Waits))
		}
		return result, ""
	}
	dir := filepath.Join(opts.OutDir, "cases", c.ID)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		result.Outcome, result.Error = Error, err.Error()
		return result, ""
	}
	timeout := c.Timeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()
	log, err := os.Create(filepath.Join(dir, "case.log"))
	if err != nil {
		result.Outcome, result.Error = Error, err.Error()
		return result, ""
	}
	defer log.Close()
	t := &T{ctx: ctx, kind: opts.Kind, c: c, dir: dir, console: console, log: log}

	if opts.GitHub {
		fmt.Fprintf(console, "::group::%s [%s] %s\n", c.ID, c.Label, c.Title)
	} else {
		fmt.Fprintf(console, "=== RUN    %s [%s] %s\n", c.ID, c.Label, c.Title)
	}
	if c.Defect != "" {
		t.write("", "known baseline defect: "+c.Defect)
	}
	started := time.Now()
	var stuck []string
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer func() {
			if p := recover(); p != nil {
				t.markError(fmt.Sprintf("panic: %v", p))
			}
		}()
		if opts.Before != nil {
			opts.Before(t)
		}
		c.Run(t)
	}()
	select {
	case <-done:
	case <-ctx.Done():
		t.markError(fmt.Sprintf("timed out after %s", timeout))
		select {
		case <-done:
		case <-time.After(timeoutGrace):
			t.markError("the case did not stop after its timeout")
			stuck = append(stuck, "the case did not stop after its timeout")
		}
	}
	// Cleanups and After run with a fresh deadline: the case's may be spent.
	cleanupCtx, cleanupCancel := context.WithTimeout(parent, cleanupTimeout)
	defer cleanupCancel()
	t.mu.Lock()
	cleanups := t.cleanups
	t.cleanups = nil
	t.ctx = cleanupCtx
	t.mu.Unlock()
	onPanic := func(p any) { t.markError(fmt.Sprintf("panic in cleanup: %v", p)) }
	for i := len(cleanups) - 1; i >= 0; i-- {
		if !runIsolated(cleanups[i], onPanic, cleanupTimeout) {
			t.markError("a cleanup did not finish within " + cleanupTimeout.String())
			stuck = append(stuck, "a cleanup did not finish")
		}
	}
	if opts.After != nil && !runIsolated(func() { opts.After(t) }, onPanic, cleanupTimeout) {
		t.markError("the after-case step did not finish within " + cleanupTimeout.String())
		stuck = append(stuck, "the after-case step did not finish")
	}

	t.mu.Lock()
	result.Checks = append([]Check(nil), t.checks...)
	result.Notes = append([]string(nil), t.notes...)
	result.Error = t.harnessErr
	t.mu.Unlock()
	var tally Tally
	for _, check := range result.Checks {
		switch {
		case check.ReleaseBlocker:
			tally.ReleaseChecks++
			if !check.OK {
				tally.ReleaseFailed++
			}
		case check.Defect:
			tally.Expects++
			if !check.OK {
				tally.ExpectFailed++
			}
		default:
			tally.Checks++
			if !check.OK {
				tally.Failed++
			}
		}
	}
	if opts.Kind == V1 && c.ReleaseBlocker != "" && tally.ReleaseChecks == 0 && result.Error == "" {
		result.Error = "a declared release blocker must measure its release checks"
		t.write("ERROR", result.Error)
	}
	var why string
	result.Outcome, why = Decide(c.Label, opts.Kind, result.Error != "", tally)
	if result.Error == "" && why != "" {
		result.Error = why
		t.write("ERROR", why)
	}
	result.DurationMS = time.Since(started).Milliseconds()

	if opts.GitHub {
		fmt.Fprintln(console, "::endgroup::")
	}
	verb := map[Outcome]string{Pass: "PASS", Fail: "FAIL", KnownDefect: "DEFECT", NotReproduced: "FAIL", Error: "FAIL", ReleaseBlocked: "BLOCKER"}[result.Outcome]
	fmt.Fprintf(console, "--- %-6s %s (%.1fs): %s\n", verb, c.ID, time.Since(started).Seconds(), Explain(result.Outcome))
	if detail := result.Detail(); detail != "" && result.Outcome != Pass {
		fmt.Fprintf(console, "           %s\n", detail)
	}
	if opts.GitHub {
		switch {
		case result.Outcome.FailsJob():
			fmt.Fprintf(console, "::error title=%s::%s: %s\n", annotationEscape(c.ID), annotationEscape(Explain(result.Outcome)), annotationEscape(result.Detail()))
		case result.Outcome == KnownDefect:
			fmt.Fprintf(console, "::notice title=%s::known baseline defect (%s): %s\n", annotationEscape(c.ID), annotationEscape(c.Defect), annotationEscape(result.Detail()))
		case result.Outcome == ReleaseBlocked:
			fmt.Fprintf(console, "::warning title=%s::release blocker: %s\n", annotationEscape(c.ID), annotationEscape(result.Detail()))
		}
	}
	return result, strings.Join(stuck, "; ")
}

// runIsolated runs fn in its own goroutine, so a Fatalf (Goexit) or a panic in
// a cleanup ends only that cleanup. It reports whether fn finished in time.
func runIsolated(fn func(), onPanic func(any), timeout time.Duration) bool {
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer func() {
			if p := recover(); p != nil {
				onPanic(p)
			}
		}()
		fn()
	}()
	select {
	case <-done:
		return true
	case <-time.After(timeout):
		return false
	}
}

func annotationEscape(text string) string {
	text = strings.ReplaceAll(text, "%", "%25")
	text = strings.ReplaceAll(text, "\r", "%0D")
	return strings.ReplaceAll(text, "\n", "%0A")
}
