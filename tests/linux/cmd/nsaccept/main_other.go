//go:build !linux

// Command nsaccept is Net Switch's Linux acceptance harness; it only runs on
// Linux (in CI). See main_linux.go.
package main

import (
	"fmt"
	"os"
)

func main() {
	fmt.Fprintln(os.Stderr, "nsaccept runs on Linux only (GitHub's Ubuntu runners); see tests/linux.")
	os.Exit(2)
}
