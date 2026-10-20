//go:build windows

package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"os"
	"os/signal"
	"path/filepath"

	winengine "github.com/AyoubAchour/net-switch/internal/engine/windows"
	winplatform "github.com/AyoubAchour/net-switch/internal/platform/windows"
	"golang.org/x/sys/windows"
)

func run(args []string) error {
	if len(args) > 0 && args[0] == "heap-capture" {
		return winengine.CaptureHeapCommand(args[1:])
	}
	// Only this read operation is exposed by the standalone engine. Reuse the
	// existing native worker protocol and isolation instead of a scripting host.
	if len(args) == 3 && args[0] == "worker" && args[1] == "query" && args[2] == "tcp-port-configuration" {
		if winplatform.Run(args[1:]) != 0 {
			return errors.New("TCP port configuration worker failed")
		}
		return nil
	}
	if len(args) == 1 && args[0] == "firewall-state" {
		state, err := winengine.FirewallState()
		if err != nil {
			return err
		}
		return json.NewEncoder(os.Stdout).Encode(state)
	}
	if len(args) == 1 && args[0] == "interfaces" {
		adapters, err := winengine.Discover()
		if err != nil {
			return err
		}
		return json.NewEncoder(os.Stdout).Encode(adapters)
	}
	if len(args) == 0 || (args[0] != "run" && args[0] != "cleanup") {
		return errors.New("usage: netswitch-engine run|cleanup [--state-dir directory] [--standalone-admin], or interfaces|firewall-state")
	}
	root, err := windows.KnownFolderPath(windows.FOLDERID_ProgramData, 0)
	if err != nil {
		return err
	}
	f := flag.NewFlagSet(args[0], flag.ContinueOnError)
	dir := f.String("state-dir", filepath.Join(root, "Net Switch"), "SYSTEM/Administrators engine state directory")
	standalone := f.Bool("standalone-admin", false, "allow elevated administrator pipe clients for standalone acceptance")
	if err := f.Parse(args[1:]); err != nil {
		return err
	}
	if f.NArg() != 0 {
		return errors.New("unexpected arguments")
	}
	if args[0] == "cleanup" {
		return winengine.Recover(*dir)
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()
	return winengine.Serve(ctx, *dir, *standalone)
}
