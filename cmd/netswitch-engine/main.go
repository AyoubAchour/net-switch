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
	// Platform capture is deliberately not wired into this binary yet.
	fmt.Fprintln(os.Stderr, "usage: netswitch-engine version")
	os.Exit(2)
}
