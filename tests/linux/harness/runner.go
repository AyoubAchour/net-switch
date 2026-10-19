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

// After a case times out, it gets this long to notice before the run moves on.
const timeoutGrace = 15 * time.Second

// Case is one acceptance case.
type Case struct {
	ID      string // stable, dotted: "udp.stun-same-mapping"
	Title   string
	Label   Label
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
		case c.Title == "" || c.Run == nil:
			return fmt.Errorf("case %s needs a title and a Run function", c.ID)
		}
		seen[c.ID] = true
	}
	return nil
}

// Check is one behavioural check a case made.
type Check struct {
	OK      bool   `json:"ok"`
	Message string `json:"message"`
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
		fmt.Fprintf(t.console, "    %-5s %s\n", prefix, line)
		if t.log != nil {
			fmt.Fprintf(t.log, "%s %-5s %s\n", stamp, prefix, line)
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

// Check records a behavioural check and reports whether it passed.
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

// Require is Check, and stops the case when the check fails. Use it when the
// rest of the case depends on this check.
func (t *T) Require(ok bool, format string, args ...any) {
	if !t.Check(ok, format, args...) {
		runtime.Goexit()
	}
}

// Fatalf records that the harness couldn't do its job and stops the case. It
// fails the run whatever the case's label.
func (t *T) Fatalf(format string, args ...any) {
	text := fmt.Sprintf(format, args...)
	t.mu.Lock()
	if t.harnessErr == "" {
		t.harnessErr = text
	}
	t.mu.Unlock()
	t.write("ERROR", text)
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

// Run runs the cases in order and returns the report.
func Run(ctx context.Context, cases []*Case, report *Report, opts Options) *Report {
	if opts.Console == nil {
		opts.Console = os.Stdout
	}
	report.Kind = opts.Kind
	for _, c := range cases {
		result := runCase(ctx, c, opts)
		report.Cases = append(report.Cases, result)
		report.finish()
		if opts.Progress != nil {
			opts.Progress(report)
		}
		if ctx.Err() != nil {
			break
		}
	}
	report.finish()
	return report
}

func runCase(parent context.Context, c *Case, opts Options) CaseResult {
	result := CaseResult{ID: c.ID, Title: c.Title, Label: c.Label, Spec: c.Spec}
	console := opts.Console
	if c.Label == Requires10 && opts.Kind == Baseline {
		result.Outcome = NotRun
		fmt.Fprintf(console, "--- SKIP  %s [%s] %s: %s\n", c.ID, c.Label, c.Title, Explain(NotRun))
		return result
	}
	dir := filepath.Join(opts.OutDir, "cases", c.ID)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		result.Outcome = Error
		result.Error = err.Error()
		return result
	}
	timeout := c.Timeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()
	log, err := os.Create(filepath.Join(dir, "case.log"))
	if err != nil {
		result.Outcome = Error
		result.Error = err.Error()
		return result
	}
	defer log.Close()
	t := &T{ctx: ctx, kind: opts.Kind, c: c, dir: dir, console: console, log: log}

	if opts.GitHub {
		fmt.Fprintf(console, "::group::%s [%s] %s\n", c.ID, c.Label, c.Title)
	} else {
		fmt.Fprintf(console, "=== RUN   %s [%s] %s\n", c.ID, c.Label, c.Title)
	}
	started := time.Now()
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
			t.markError("the case did not stop after its timeout; continuing without it")
		}
	}
	// Cleanups and After run with a fresh deadline: the case's may be spent.
	cleanupCtx, cleanupCancel := context.WithTimeout(parent, 60*time.Second)
	defer cleanupCancel()
	t.mu.Lock()
	cleanups := t.cleanups
	t.cleanups = nil
	t.ctx = cleanupCtx
	t.mu.Unlock()
	onPanic := func(p any) { t.markError(fmt.Sprintf("panic in cleanup: %v", p)) }
	for i := len(cleanups) - 1; i >= 0; i-- {
		runIsolated(cleanups[i], onPanic)
	}
	if opts.After != nil {
		runIsolated(func() { opts.After(t) }, onPanic)
	}

	t.mu.Lock()
	result.Checks = append([]Check(nil), t.checks...)
	result.Notes = append([]string(nil), t.notes...)
	result.Error = t.harnessErr
	t.mu.Unlock()
	failed := 0
	for _, check := range result.Checks {
		if !check.OK {
			failed++
		}
	}
	result.Outcome = Decide(c.Label, opts.Kind, result.Error != "", len(result.Checks), failed)
	if result.Outcome == Error && result.Error == "" {
		result.Error = "the case made no checks"
	}
	result.DurationMS = time.Since(started).Milliseconds()

	if opts.GitHub {
		fmt.Fprintln(console, "::endgroup::")
	}
	verb := map[Outcome]string{Pass: "PASS", Fail: "FAIL", KnownDefect: "DEFECT", NotReproduced: "FAIL", Error: "FAIL"}[result.Outcome]
	fmt.Fprintf(console, "--- %-6s %s (%.1fs): %s\n", verb, c.ID, time.Since(started).Seconds(), Explain(result.Outcome))
	if detail := result.Detail(); detail != "" && result.Outcome != Pass {
		fmt.Fprintf(console, "           %s\n", detail)
	}
	if opts.GitHub {
		switch {
		case result.Outcome.FailsJob():
			fmt.Fprintf(console, "::error title=%s::%s: %s\n", annotationEscape(c.ID), annotationEscape(Explain(result.Outcome)), annotationEscape(result.Detail()))
		case result.Outcome == KnownDefect:
			fmt.Fprintf(console, "::notice title=%s::known baseline defect: %s\n", annotationEscape(c.ID), annotationEscape(result.Detail()))
		}
	}
	return result
}

// runIsolated runs fn in its own goroutine, so a Fatalf (Goexit) or a panic in
// a cleanup ends only that cleanup.
func runIsolated(fn func(), onPanic func(any)) {
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
	<-done
}

func annotationEscape(text string) string {
	text = strings.ReplaceAll(text, "%", "%25")
	text = strings.ReplaceAll(text, "\r", "%0D")
	return strings.ReplaceAll(text, "\n", "%0A")
}
