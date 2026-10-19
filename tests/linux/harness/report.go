package harness

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Executable identifies a program the run tested or ran with.
type Executable struct {
	Role    string `json:"role"` // "engine", "harness"
	Name    string `json:"name"`
	Path    string `json:"path"`
	Version string `json:"version"`
	SHA256  string `json:"sha256"`
}

// CaseResult is a case's entry in the report.
type CaseResult struct {
	ID         string   `json:"id"`
	Title      string   `json:"title"`
	Label      Label    `json:"label"`
	Spec       string   `json:"spec,omitempty"`
	Outcome    Outcome  `json:"outcome"`
	DurationMS int64    `json:"durationMs"`
	Checks     []Check  `json:"checks,omitempty"`
	Notes      []string `json:"notes,omitempty"`
	Error      string   `json:"error,omitempty"`
}

// Detail is the most useful single line about a result: the harness error, or
// the first failed check.
func (r CaseResult) Detail() string {
	if r.Error != "" {
		return r.Error
	}
	for _, check := range r.Checks {
		if !check.OK {
			return check.Message
		}
	}
	return ""
}

// Report is a whole run.
type Report struct {
	StartedAt   time.Time         `json:"startedAt"`
	FinishedAt  time.Time         `json:"finishedAt"`
	Kind        EngineKind        `json:"engineKind"`
	Executables []Executable      `json:"executables"`
	System      map[string]string `json:"system"`
	Cases       []CaseResult      `json:"cases"`
	Totals      map[Outcome]int   `json:"totals"`
	JobFailed   bool              `json:"jobFailed"`
	// Problems are run-level failures outside any case (for example a case
	// filter that matched nothing).
	Problems []string `json:"problems,omitempty"`
}

// NewReport starts a report.
func NewReport() *Report {
	return &Report{StartedAt: time.Now().UTC(), System: map[string]string{}, Totals: map[Outcome]int{}}
}

// Fail records a run-level problem; it fails the job.
func (r *Report) Fail(format string, args ...any) {
	r.Problems = append(r.Problems, fmt.Sprintf(format, args...))
	r.finish()
}

func (r *Report) finish() {
	r.FinishedAt = time.Now().UTC()
	r.Totals = map[Outcome]int{}
	r.JobFailed = len(r.Problems) > 0
	for _, c := range r.Cases {
		r.Totals[c.Outcome]++
		if c.Outcome.FailsJob() {
			r.JobFailed = true
		}
	}
}

// WriteFiles writes report.json and summary.md into dir.
func (r *Report) WriteFiles(dir string) error {
	r.finish()
	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	if err := writeAtomic(filepath.Join(dir, "report.json"), append(data, '\n')); err != nil {
		return err
	}
	var md strings.Builder
	r.WriteMarkdown(&md)
	return writeAtomic(filepath.Join(dir, "summary.md"), []byte(md.String()))
}

func writeAtomic(path string, data []byte) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// WriteMarkdown writes the summary shown in the GitHub job page.
func (r *Report) WriteMarkdown(w io.Writer) {
	verdict := "passed"
	if r.JobFailed {
		verdict = "**failed**"
	}
	fmt.Fprintf(w, "## Linux acceptance (%s engine): %s\n\n", r.Kind, verdict)
	if len(r.Executables) > 0 {
		fmt.Fprintln(w, "| Role | Program | Version | SHA-256 | Path |")
		fmt.Fprintln(w, "|---|---|---|---|---|")
		for _, e := range r.Executables {
			fmt.Fprintf(w, "| %s | %s | %s | `%s` | `%s` |\n", e.Role, e.Name, mdCell(e.Version), e.SHA256, e.Path)
		}
		fmt.Fprintln(w)
	}
	if len(r.System) > 0 {
		keys := make([]string, 0, len(r.System))
		for key := range r.System {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		parts := make([]string, 0, len(keys))
		for _, key := range keys {
			parts = append(parts, fmt.Sprintf("%s: %s", key, r.System[key]))
		}
		fmt.Fprintf(w, "%s\n\n", strings.Join(parts, " · "))
	}
	order := []Outcome{Pass, KnownDefect, NotRun, Fail, NotReproduced, Error}
	var counts []string
	for _, o := range order {
		if n := r.Totals[o]; n > 0 {
			counts = append(counts, fmt.Sprintf("%d %s", n, o))
		}
	}
	fmt.Fprintf(w, "%s\n\n", strings.Join(counts, ", "))
	for _, problem := range r.Problems {
		fmt.Fprintf(w, "- **Run problem:** %s\n", mdCell(problem))
	}
	if len(r.Problems) > 0 {
		fmt.Fprintln(w)
	}
	fmt.Fprintln(w, "| Case | Label | Outcome | Time | Detail |")
	fmt.Fprintln(w, "|---|---|---|---|---|")
	for _, c := range r.Cases {
		outcome := string(c.Outcome)
		if c.Outcome.FailsJob() {
			outcome = "**" + outcome + "**"
		}
		detail := c.Detail()
		if c.Outcome == Pass && len(c.Notes) > 0 {
			detail = c.Notes[0]
		}
		fmt.Fprintf(w, "| `%s` | %s | %s | %.1fs | %s |\n", c.ID, c.Label, outcome, float64(c.DurationMS)/1000, mdCell(detail))
	}
	fmt.Fprintln(w)
}

func mdCell(text string) string {
	text = strings.ReplaceAll(text, "|", "\\|")
	text = strings.ReplaceAll(text, "\n", " ")
	if len(text) > 300 {
		text = text[:297] + "..."
	}
	return text
}
