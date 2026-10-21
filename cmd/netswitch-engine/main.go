package main

import (
	"fmt"
	"os"

	"github.com/AyoubAchour/net-switch/internal/buildinfo"
)

func main() {
	if len(os.Args) == 2 && os.Args[1] == "version" {
		fmt.Println("netswitch-engine", buildinfo.String())
		return
	}
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "netswitch-engine:", err)
		os.Exit(exitCode(err))
	}
}

func exitCode(err error) int {
	if err == nil {
		return 0
	}
	// Only a direct, completed platform outcome may override failure.
	// Do not search through joined cleanup errors for a clean exit reason.
	if outcome, ok := err.(interface{ EngineExitCode() int }); ok {
		return outcome.EngineExitCode()
	}
	return 1
}
