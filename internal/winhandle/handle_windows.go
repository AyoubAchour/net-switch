//go:build windows

// Package winhandle makes native ownership explicit. The handlecheck build
// records generations and rejects stale uses/closes before calling Windows.
package winhandle

import "golang.org/x/sys/windows"

type Owner struct {
	value      windows.Handle
	generation uint64
}

func (o Owner) IsZero() bool { return o.generation == 0 }

// Open records a newly obtained handle, not a second owner of an existing one.
// A copy of Owner is a borrowed reference to the same generation.
func Open(value windows.Handle, site string) Owner {
	return Owner{value, opened(value, site)}
}

// OpenDriverHandle is only for a device whose documented protocol can close
// its user's handle during removal. A fresh OS allocation of that value proves
// that generation ended; it never licenses another close of the old value.
func OpenDriverHandle(value windows.Handle, site string) Owner {
	o := Open(value, site)
	driverOwned(o)
	return o
}

// DriverReleased ends ownership after observing the driver's release marker.
// It performs no Windows close and cannot close a newly reused handle value.
func (o Owner) DriverReleased(site string) { driverReleased(o, site) }

func (o Owner) Handle(site string) windows.Handle {
	used(o, site, false)
	return o.value
}

// GoBorrow is only valid inside a successful SyscallConn.Control callback.
// Go may already be closing the descriptor, but its reference count keeps that
// callback's handle alive until the callback returns.
func (o Owner) GoBorrow(site string) windows.Handle {
	used(o, site, true)
	return o.value
}

func (o Owner) Close(site string, close func(windows.Handle) error) error {
	closing(o, site, false)
	err := close(o.value)
	closed(o, site, err)
	return err
}

// CloseGo records a close performed by the Go owner. It does not call a raw
// close itself. The caller must preserve that Go owner's idempotent Close
// contract; raw values are never closed a second time as a fallback.
func (o Owner) CloseGo(site string, close func() error) error {
	closing(o, site, true)
	err := close()
	closed(o, site, err)
	return err
}

func (o Owner) SocketClose(site string) error { return o.Close(site, windows.Closesocket) }
func (o Owner) HandleClose(site string) error { return o.Close(site, windows.CloseHandle) }
