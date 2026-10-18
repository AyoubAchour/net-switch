package main

import (
	"errors"
	"fmt"
	"os"
	"time"

	"golang.org/x/sys/windows"
)

func runOptions(opts options) int {
	var sample func() any
	switch opts.mode {
	case "run":
		return runHidden(opts.program, opts.programArgs)
	case "policy":
		policy, err := readPolicy()
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		if err := writeLine(map[string]any{"policy": policy}); err != nil {
			return 1
		}
		return 0
	case "probe":
		if err := writeLine(probe(opts)); err != nil {
			return 1
		}
		return 0
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
	if opts.mode == "network" {
		if err := network(opts.once); err != nil {
			fmt.Fprintf(os.Stderr, "network: %v\n", err)
			return 1
		}
		return 0
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
