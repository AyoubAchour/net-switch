//go:build linux

package main

import (
	"context"
	"errors"
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/AyoubAchour/net-switch/internal/engine/linux"
)

func run(args []string) error {
	if len(args) == 0 || (args[0] != "run" && args[0] != "cleanup") {
		return errors.New("usage: netswitch-engine version|service|worker|run|cleanup [--socket path] [--state-dir directory]")
	}
	f := flag.NewFlagSet(args[0], flag.ContinueOnError)
	socket := f.String("socket", "/run/netswitch/engine.sock", "root-only control socket")
	state := f.String("state-dir", "/var/lib/netswitch", "private ownership/state directory")
	profiles := f.String("profile-dir", "", "private diagnostics directory; SIGUSR1 captures heap and goroutine profiles")
	cpuProfile := f.Bool("cpu-profile", false, "record CPU and sampled contention profiles in the diagnostics directory")
	traceProfile := f.Bool("trace-profile", false, "record the first five seconds of runtime scheduling in the diagnostics directory")
	if err := f.Parse(args[1:]); err != nil {
		return err
	}
	if f.NArg() != 0 {
		return errors.New("unexpected arguments")
	}
	if os.Geteuid() != 0 {
		return errors.New("engine must run as root")
	}
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer cancel()
	if args[0] == "cleanup" {
		ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
		defer cancel()
		p, err := linux.New(ctx, *state)
		if err != nil {
			return err
		}
		return p.Close()
	}
	if err := configureScheduling(); err != nil {
		log.Printf("routing CPU scheduling remains inherited: %v", err)
	}
	stopProfiles, err := startProfiles(*profiles, *cpuProfile, *traceProfile)
	if err != nil {
		return err
	}
	defer stopProfiles()
	return linux.Serve(ctx, *socket, *state, installTestHooks)
}
