// Command netswitchctl installs, migrates, recovers and diagnoses Net Switch
// 1.0. Only "version" works so far; the rest arrives with the 1.0 milestones.
package main

import (
	"fmt"
	"os"

	"github.com/AyoubAchour/net-switch/internal/buildinfo"
)

func main() {
	if len(os.Args) == 2 && os.Args[1] == "version" {
		fmt.Println("netswitchctl", buildinfo.String())
		return
	}
	fmt.Fprintln(os.Stderr, "usage: netswitchctl version")
	os.Exit(2)
}
