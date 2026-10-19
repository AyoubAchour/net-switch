// Command netswitchctl installs, migrates, recovers and diagnoses Net Switch
// 1.0. Linux engine journal cleanup is available alongside "version".
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
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "netswitchctl:", err)
		os.Exit(1)
	}
}
