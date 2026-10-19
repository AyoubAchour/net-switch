//go:build linux

package main

import (
	"context"
	"errors"
	"flag"
	"github.com/AyoubAchour/net-switch/internal/engine/linux"
	"os"
	"time"
)

func run(args []string) error {
	if len(args) == 0 || args[0] != "cleanup" {
		return errors.New("usage: netswitchctl version | cleanup --engine [--state-dir directory]")
	}
	f := flag.NewFlagSet("cleanup", flag.ContinueOnError)
	engine := f.Bool("engine", false, "clean engine ownership journal")
	dir := f.String("state-dir", "/var/lib/netswitch", "private engine state directory")
	if err := f.Parse(args[1:]); err != nil {
		return err
	}
	if !*engine || f.NArg() != 0 {
		return errors.New("cleanup requires --engine")
	}
	if os.Geteuid() != 0 {
		return errors.New("cleanup requires root")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	p, err := linux.New(ctx, *dir)
	if err != nil {
		return err
	}
	return p.Close()
}
