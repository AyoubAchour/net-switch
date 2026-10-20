package lifecycle

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

func DefaultData() string                      { return "/var/lib/netswitch" }
func PrepareStore(path string) (string, error) { return path, PrepareDirectory(path) }
func ResolveStore(path string) (string, error) { return path, nil }
func Administrator() bool                      { return os.Geteuid() == 0 }
func CurrentUser() string                      { return strconv.Itoa(os.Getuid()) }
func ResolveOwner(name string) (Owner, error) {
	if name == "" {
		name = os.Getenv("SUDO_UID")
		if name == "" {
			name = os.Getenv("PKEXEC_UID")
		}
		if name == "" {
			return Owner{}, errors.New("enrolment pending: specify the interactive user")
		}
	}
	u, err := user.LookupId(name)
	if err != nil {
		u, err = user.Lookup(name)
	}
	if err != nil {
		return Owner{}, err
	}
	return Owner{User: u.Uid, Name: u.Username}, nil
}
func PrepareDirectory(path string) error {
	if !Administrator() {
		return errors.New("creating the service store requires root")
	}
	if err := os.MkdirAll(path, 0700); err != nil {
		return err
	}
	return CheckDirectory(path)
}
func CheckDirectory(path string) error {
	if !filepath.IsAbs(path) {
		return errors.New("service store needs an absolute path")
	}
	for p := filepath.Clean(path); ; p = filepath.Dir(p) {
		info, err := os.Lstat(p)
		if err != nil {
			return err
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || !info.IsDir() || stat.Uid != 0 || info.Mode().Perm()&0022 != 0 {
			return fmt.Errorf("untrusted service directory %s", p)
		}
		if p == "/" {
			break
		}
	}
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	if info.Mode().Perm()&0077 != 0 {
		return errors.New("service data must have mode 0700")
	}
	return nil
}
func SyncDirectory(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}
func durableRename(from, to string) error { return os.Rename(from, to) }
func writeStoreFile(path string, data []byte, mode os.FileMode) error {
	return os.WriteFile(path, data, mode)
}
func BootID() (string, error) {
	b, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	return strings.TrimSpace(string(b)), err
}

type Lock struct{ Data, Name string }

func (l Lock) Acquire(ctx context.Context) (func() error, error) {
	fd, err := unix.Open(filepath.Join(l.Data, l.Name+".lock"), unix.O_CREAT|unix.O_RDWR|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0600)
	if err != nil {
		return nil, err
	}
	for {
		err = unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB)
		if err == nil {
			return func() error { return unix.Close(fd) }, nil
		}
		if err != unix.EWOULDBLOCK {
			unix.Close(fd)
			return nil, err
		}
		select {
		case <-ctx.Done():
			unix.Close(fd)
			return nil, ctx.Err()
		case <-time.After(20 * time.Millisecond):
		}
	}
}
