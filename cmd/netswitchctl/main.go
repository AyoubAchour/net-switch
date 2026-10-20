// Command netswitchctl manages 1.0 services, enrollment and recovery.
// The 0.3.x migration transaction belongs to milestone five.
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
