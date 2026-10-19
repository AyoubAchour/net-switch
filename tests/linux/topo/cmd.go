//go:build linux

package topo

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"
)

// Runner runs the system tools (ip, nft, tc, sysctl) the topology is built
// with, logging each command and its output.
type Runner struct {
	mu  sync.Mutex
	log io.Writer
}

// NewRunner logs to w (nil: nowhere).
func NewRunner(w io.Writer) *Runner {
	if w == nil {
		w = io.Discard
	}
	return &Runner{log: w}
}

func (r *Runner) logf(format string, args ...any) {
	r.mu.Lock()
	defer r.mu.Unlock()
	fmt.Fprintf(r.log, "%s "+format+"\n", append([]any{time.Now().UTC().Format("15:04:05.000")}, args...)...)
}

// Run runs a command and returns its combined output; a failure's error
// includes the command and what it printed.
func (r *Runner) Run(ctx context.Context, name string, args ...string) (string, error) {
	return r.RunInput(ctx, "", name, args...)
}

// RunInput is Run with text on standard input (for `ip -batch -`, `nft -f -`).
func (r *Runner) RunInput(ctx context.Context, input, name string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	if input != "" {
		cmd.Stdin = strings.NewReader(input)
	}
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	cmd.WaitDelay = 5 * time.Second
	err := cmd.Run()
	text := strings.TrimSpace(out.String())
	line := name + " " + strings.Join(args, " ")
	if input != "" {
		line += fmt.Sprintf(" <<%d lines>>", strings.Count(input, "\n")+1)
	}
	if err != nil {
		r.logf("$ %s\n    -> %v: %s", line, err, text)
		return text, fmt.Errorf("%s: %v: %s", line, err, text)
	}
	if text != "" {
		r.logf("$ %s\n    %s", line, strings.ReplaceAll(text, "\n", "\n    "))
	} else {
		r.logf("$ %s", line)
	}
	return text, nil
}

// Must runs a list of commands, stopping at the first failure.
func (r *Runner) Must(ctx context.Context, cmds ...[]string) error {
	for _, c := range cmds {
		if _, err := r.Run(ctx, c[0], c[1:]...); err != nil {
			return err
		}
	}
	return nil
}

// In runs a command inside a namespace.
func (r *Runner) In(ctx context.Context, ns string, name string, args ...string) (string, error) {
	return r.Run(ctx, "ip", append([]string{"netns", "exec", ns, name}, args...)...)
}

// IP runs `ip -n ns ...`.
func (r *Runner) IP(ctx context.Context, ns string, args ...string) (string, error) {
	return r.Run(ctx, "ip", append([]string{"-n", ns}, args...)...)
}

// Batch runs `ip -n ns -batch -` with one command per line.
func (r *Runner) Batch(ctx context.Context, ns string, lines []string) error {
	if len(lines) == 0 {
		return nil
	}
	_, err := r.RunInput(ctx, strings.Join(lines, "\n")+"\n", "ip", "-n", ns, "-batch", "-")
	return err
}

// Sysctl sets kernel settings inside a namespace.
func (r *Runner) Sysctl(ctx context.Context, ns string, settings ...string) error {
	args := append([]string{"-q", "-w"}, settings...)
	_, err := r.In(ctx, ns, "sysctl", args...)
	return err
}

// Nft loads an nftables script inside a namespace.
func (r *Runner) Nft(ctx context.Context, ns, script string) error {
	_, err := r.RunInput(ctx, script, "ip", "netns", "exec", ns, "nft", "-f", "-")
	return err
}

// Process is a background program the topology started; Down stops it.
type Process struct {
	Name    string
	Cmd     *exec.Cmd
	done    chan struct{}
	err     error
	logPath string
}

// Done is closed when the process exits.
func (p *Process) Done() <-chan struct{} { return p.done }

// Err is how the process ended, once Done is closed.
func (p *Process) Err() error { return p.err }

// Stop kills the process and waits for it, and says if it couldn't.
func (p *Process) Stop() error {
	if p.Cmd.Process != nil {
		if err := p.Cmd.Process.Kill(); err != nil && !errors.Is(err, os.ErrProcessDone) {
			return fmt.Errorf("killing %s: %w", p.Name, err)
		}
	}
	select {
	case <-p.done:
		return nil
	case <-time.After(5 * time.Second):
		return fmt.Errorf("%s didn't exit within 5 s of SIGKILL", p.Name)
	}
}

// StartLogged starts a background command whose output goes to logPath, and
// waits until that log contains ready (if ready isn't empty).
func StartLogged(ctx context.Context, name, logPath, ready string, timeout time.Duration, argv ...string) (*Process, error) {
	logFile, err := os.Create(logPath)
	if err != nil {
		return nil, err
	}
	cmd := exec.Command(argv[0], argv[1:]...)
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	if err := cmd.Start(); err != nil {
		logFile.Close()
		return nil, fmt.Errorf("start %s: %w", name, err)
	}
	p := &Process{Name: name, Cmd: cmd, done: make(chan struct{}), logPath: logPath}
	go func() {
		p.err = cmd.Wait()
		logFile.Close()
		close(p.done)
	}()
	if ready == "" {
		return p, nil
	}
	deadline := time.Now().Add(timeout)
	for {
		data, _ := os.ReadFile(logPath)
		if bytes.Contains(data, []byte(ready)) {
			return p, nil
		}
		select {
		case <-p.done:
			return nil, fmt.Errorf("%s exited before it was ready (%v): %s", name, p.err, lastLines(data, 10))
		case <-ctx.Done():
			return nil, errors.Join(ctx.Err(), p.Stop())
		case <-time.After(50 * time.Millisecond):
		}
		if time.Now().After(deadline) {
			return nil, errors.Join(fmt.Errorf("%s wasn't ready within %s: %s", name, timeout, lastLines(data, 10)), p.Stop())
		}
	}
}

func lastLines(data []byte, n int) string {
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, " | ")
}
