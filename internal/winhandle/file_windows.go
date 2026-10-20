//go:build windows

package winhandle

import (
	"os"
	"sync"
)

// File transfers an already-owned kernel handle to os.File. Close remains
// idempotent at the Go object boundary, while exactly one native generation
// ends. The raw handle is never also closed by the former owner.
type File struct {
	*os.File
	owner  Owner
	mu     sync.Mutex
	closed bool
}

func NewFile(owner Owner, name string) *File {
	return &File{File: os.NewFile(uintptr(owner.Handle("transfer kernel handle to Go file")), name), owner: owner}
}

func (f *File) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed {
		return os.ErrClosed
	}
	f.closed = true
	return f.owner.CloseGo("Go file close: "+f.Name(), f.File.Close)
}

func (f *File) Fd() uintptr {
	f.owner.Handle("Go file native handle borrow")
	return f.File.Fd()
}
