// The netswitch worker subcommand folds the helper's meter, outside, network,
// probe and policy modes into the control executable. Each runs independently
// with pipe-only output and bounded lifetime; workers cannot launch programs.
// query-supervised exercises the same restricted-process boundary as Control,
// including its deadline and stderr handling, for native parity diagnostics.
package winplatform

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"math"
	"os"
)

type options struct {
	mode    string
	parent  uint32
	engine  string
	once    bool
	index   uint
	targets string
	timeout int
	// For run: the program and its arguments, passed on unchanged.
	program     string
	programArgs []string
}

const usage = `usage:
  netswitch worker meters  [--parent PID] [--once]
  netswitch worker outside [--parent PID] [--engine PATH] [--once]
  netswitch worker network [--parent PID] [--once]
  netswitch worker probe --interface-index N --targets IP:PORT,IP:PORT [--timeout-ms 2000]
  netswitch worker policy
  netswitch worker query OPERATION [BASE64URL_ARGS]
  netswitch worker query-supervised OPERATION [BASE64URL_ARGS]`

// Run executes one blocking read mode in a disposable worker process.
func Run(args []string) int {
	if len(args) > 0 && args[0] == "query" {
		return query(args[1:], false)
	}
	if len(args) > 0 && args[0] == "query-supervised" {
		return query(args[1:], true)
	}
	return run(args)
}

func run(args []string) int {
	opts, err := parseArgs(args)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n%s\n", err, usage)
		return 2
	}

	return runOptions(opts)
}

func parseArgs(args []string) (options, error) {
	if len(args) == 0 {
		return options{}, errors.New("choose a mode: meters, outside, network, probe, policy or run")
	}
	opts := options{mode: args[0]}
	// Everything after the program belongs to it, flags included.
	if opts.mode == "run" {
		return options{}, errors.New("workers cannot launch arbitrary programs")
	}
	if opts.mode != "meters" && opts.mode != "outside" && opts.mode != "network" && opts.mode != "probe" && opts.mode != "policy" {
		return options{}, fmt.Errorf("unknown mode %q", opts.mode)
	}
	flags := flag.NewFlagSet(opts.mode, flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	parent := flags.Uint64("parent", 0, "")
	flags.BoolVar(&opts.once, "once", false, "")
	if opts.mode == "outside" {
		flags.StringVar(&opts.engine, "engine", "", "")
	}
	if opts.mode == "probe" {
		flags.UintVar(&opts.index, "interface-index", 0, "")
		flags.StringVar(&opts.targets, "targets", "", "")
		flags.IntVar(&opts.timeout, "timeout-ms", 2000, "")
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
	if opts.mode == "probe" {
		if opts.index == 0 || opts.index > math.MaxUint32 || opts.timeout <= 0 || opts.timeout > 60_000 {
			return options{}, errors.New("probe needs a valid interface index and timeout (1..60000 ms)")
		}
		if _, err := probeTargets(opts.targets); err != nil {
			return options{}, err
		}
	}
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

// The server holds the other end of standard input and never writes to it.
// When the server ends, Windows closes that end and this read finishes.
func exitAtEndOfInput() {
	if _, err := io.Copy(io.Discard, os.Stdin); err != nil {
		fmt.Fprintf(os.Stderr, "stopped watching standard input: %v\n", err)
		return
	}
	os.Exit(0)
}
