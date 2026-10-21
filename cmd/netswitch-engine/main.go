package main

import (
	"fmt"
	"os"

	"github.com/AyoubAchour/net-switch/internal/buildinfo"
	"github.com/AyoubAchour/net-switch/internal/lifecycle"
	"github.com/AyoubAchour/net-switch/internal/service"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "worker" {
		os.Exit(lifecycle.Worker(os.Args[2:]))
	}
	if len(os.Args) > 1 && os.Args[1] == "service" {
		if err := lifecycle.ServiceCommand(service.Engine, os.Args[2:]); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}
	if len(os.Args) == 2 && os.Args[1] == "version" {
		fmt.Println("netswitch-engine", buildinfo.String())
		return
	}
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "netswitch-engine:", err)
		os.Exit(1)
	}
}
