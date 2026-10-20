// Command netswitch-cleanup is the installer's offline machine-data cleanup.
// It never starts Control, an engine, or a network worker.
package main

import (
	"fmt"
	"os"
	"path/filepath"

	win "github.com/AyoubAchour/net-switch/internal/platform/windows"
	"golang.org/x/sys/windows"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run() error {
	if len(os.Args) != 2 || (os.Args[1] != "--prepare" && os.Args[1] != "--remove") {
		return fmt.Errorf("expected --prepare or --remove")
	}
	parent, err := windows.KnownFolderPath(windows.FOLDERID_ProgramData, 0)
	if err != nil {
		return err
	}
	path := filepath.Join(parent, "Net Switch")
	log := func(s string) { fmt.Fprintln(os.Stderr, s) }
	if os.Args[1] == "--prepare" {
		return win.PrepareMachineUninstall(path, log)
	}
	return win.CleanupMachineData(path, log)
}
