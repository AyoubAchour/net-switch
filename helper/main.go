// Command netswitch-helper reads, once a second, what Net Switch's server needs
// from Windows and prints each reading as one line of JSON. It has two modes:
//
//   - meters: bytes per network adapter, so the line meters show the real load.
//   - outside: TCP connections that go around the routing engine, for example
//     a download that was already running when routing started.
//
// Usage:
//
//	netswitch-helper.exe meters  [--parent PID] [--once]
//	netswitch-helper.exe outside [--parent PID] [--engine PATH] [--once]
//
// It replaces two long-running PowerShell processes that printed the same
// lines and used about a hundred megabytes each. The server still runs each
// mode as its own process, so one Windows call that gets stuck can't blind the
// other. Both end by themselves when the server (--parent) exits, and when
// their standard input closes. Only readings go to standard output; anything
// else goes to standard error.
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"math"
	"os"
	"time"

	"golang.org/x/sys/windows"
)

type options struct {
	mode   string
	parent uint32
	engine string
	once   bool
}

const usage = `usage:
  netswitch-helper.exe meters  [--parent PID] [--once]
  netswitch-helper.exe outside [--parent PID] [--engine PATH] [--once]`

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	opts, err := parseArgs(args)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n%s\n", err, usage)
		return 2
	}

	var sample func() any
	switch opts.mode {
	case "meters":
		sample = func() any { return readMeters() }
	case "outside":
		watcher := newOutsideWatcher(opts.engine, windowsTCP())
		sample = func() any { return watcher.sample() }
	}

	if !opts.once {
		if opts.parent != 0 {
			if err := exitWithParent(opts.parent); err != nil {
				// No such process: the server is already gone.
				if errors.Is(err, windows.ERROR_INVALID_PARAMETER) {
					return 0
				}
				fmt.Fprintf(os.Stderr, "can't watch the server (process %d), so only a closed input will stop this helper: %v\n", opts.parent, err)
			}
		}
		go exitAtEndOfInput()
	}

	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		if err := writeLine(sample()); err != nil {
			// Nobody is reading any more.
			fmt.Fprintf(os.Stderr, "can't write a reading: %v\n", err)
			return 1
		}
		if opts.once {
			return 0
		}
		<-ticker.C
	}
}

func parseArgs(args []string) (options, error) {
	if len(args) == 0 {
		return options{}, errors.New("choose a mode: meters or outside")
	}
	opts := options{mode: args[0]}
	if opts.mode != "meters" && opts.mode != "outside" {
		return options{}, fmt.Errorf("unknown mode %q", opts.mode)
	}
	flags := flag.NewFlagSet(opts.mode, flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	parent := flags.Uint64("parent", 0, "")
	flags.BoolVar(&opts.once, "once", false, "")
	if opts.mode == "outside" {
		flags.StringVar(&opts.engine, "engine", "", "")
	}
	if err := flags.Parse(args[1:]); err != nil {
		return options{}, err
	}
	if flags.NArg() > 0 {
		return options{}, fmt.Errorf("unexpected argument %q", flags.Arg(0))
	}
	if *parent > math.MaxUint32 {
		return options{}, fmt.Errorf("--parent %d is not a process id", *parent)
	}
	opts.parent = uint32(*parent)
	return opts, nil
}

// One reading, as one write ending in a newline, so the server never sees half
// a line.
func writeLine(reading any) error {
	line, err := json.Marshal(reading)
	if err != nil {
		return err
	}
	_, err = os.Stdout.Write(append(line, '\n'))
	return err
}

// Windows doesn't end child processes with their parent, so the helper waits
// on the server's process and ends the moment it is gone, even after a crash.
func exitWithParent(pid uint32) error {
	process, err := windows.OpenProcess(windows.SYNCHRONIZE, false, pid)
	if err != nil {
		return err
	}
	go func() {
		windows.WaitForSingleObject(process, windows.INFINITE)
		os.Exit(0)
	}()
	return nil
}

// The server holds the other end of standard input and never writes to it.
// When the server ends, Windows closes that end and this read finishes.
func exitAtEndOfInput() {
	if _, err := io.Copy(io.Discard, os.Stdin); err != nil {
		fmt.Fprintf(os.Stderr, "stopped watching standard input: %v\n", err)
		return
	}
	os.Exit(0)
}
