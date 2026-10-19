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
		os.Exit(1)
	}
}
