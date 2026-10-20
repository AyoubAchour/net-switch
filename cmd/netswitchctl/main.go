// Command netswitchctl installs, migrates, recovers and diagnoses Net Switch
// 1.0. Only "version" works so far; the rest arrives with the 1.0 milestones.
package main

import (
	"fmt"
	"os"

	"github.com/AyoubAchour/net-switch/internal/lifecycle"
)

func main() {
	if err := lifecycle.Ctl(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
