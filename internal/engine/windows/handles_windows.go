//go:build windows

package winengine

import (
	"syscall"

	"github.com/AyoubAchour/net-switch/internal/winhandle"
	"golang.org/x/sys/windows"
)

func ownGoDescriptor(value interface {
	SyscallConn() (syscall.RawConn, error)
}, site string) (winhandle.Owner, error) {
	raw, err := value.SyscallConn()
	if err != nil {
		return winhandle.Owner{}, err
	}
	var owner winhandle.Owner
	err = raw.Control(func(handle uintptr) {
		owner = winhandle.Open(windows.Handle(handle), site)
	})
	return owner, err
}
