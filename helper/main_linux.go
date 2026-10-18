package main

import (
	"fmt"
	"os"
)

func runOptions(opts options) int {
	fmt.Fprintf(os.Stderr, "%s: not supported on this system yet\n", opts.mode)
	return 1
}
