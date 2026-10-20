package service

import (
	"fmt"
	"os"
	"syscall"
)

func checkInstalledPath(path string, _ bool) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 0 || info.Mode().Perm()&0022 != 0 || info.Mode()&os.ModeSymlink != 0 ||
		!info.IsDir() && (!info.Mode().IsRegular() || stat.Nlink != 1) {
		return fmt.Errorf("installation path must be root-owned and not writable by other users: %s", path)
	}
	return nil
}
