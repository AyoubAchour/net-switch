package service

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
)

// CheckInstallation verifies executable bytes and the namespaces used to find
// them, including DLLs and the adapter's adjacent verification manifest.
func CheckInstallation(directory, adapter string) error {
	for _, dir := range []string{directory, filepath.Dir(adapter)} {
		if !filepath.IsAbs(dir) {
			return fmt.Errorf("installation needs absolute paths")
		}
		for parent := filepath.Dir(dir); ; parent = filepath.Dir(parent) {
			if err := checkInstalledPath(parent, true); err != nil {
				return err
			}
			if filepath.Dir(parent) == parent {
				break
			}
		}
		if err := filepath.WalkDir(dir, func(path string, entry os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			return checkInstalledPath(path, false)
		}); err != nil {
			return err
		}
	}
	for _, name := range []string{"netswitch", "netswitch-engine", "netswitch-desktop", "netswitchctl"} {
		if runtime.GOOS == "windows" {
			name += ".exe"
		}
		info, err := os.Lstat(filepath.Join(directory, name))
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("service executable is not a regular file: %s", name)
		}
	}
	info, err := os.Lstat(adapter)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("adapter is not a regular file")
	}
	return nil
}
