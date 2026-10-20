//go:build windows

package winengine

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"
)

const EnginePipe = `\\.\pipe\ProtectedPrefix\Administrators\NetSwitch\engine`

var errPeerRefused = errors.New("engine pipe peer refused")

type Pipe struct {
	name       string
	standalone bool
	mu         sync.Mutex
	pending    windows.Handle
	closed     bool
	first      bool
	accepting  bool
}

func ListenPipe(name string, standalone bool) (*Pipe, error) {
	if name != EnginePipe {
		return nil, errors.New("engine pipe must use the protected fixed name")
	}
	p := &Pipe{name: name, standalone: standalone, first: true}
	h, err := p.create()
	if err != nil {
		return nil, err
	}
	p.pending = h
	return p, nil
}

func (p *Pipe) create() (windows.Handle, error) {
	acl := "D:P(A;;GA;;;SY)"
	if p.standalone {
		acl = "D:P(A;;GA;;;SY)(A;;GRGW;;;BA)"
	}
	sa, err := security(acl)
	if err != nil {
		return 0, err
	}
	name, err := windows.UTF16PtrFromString(p.name)
	if err != nil {
		return 0, err
	}
	mode := uint32(windows.PIPE_ACCESS_DUPLEX | windows.FILE_FLAG_OVERLAPPED)
	if p.first {
		mode |= windows.FILE_FLAG_FIRST_PIPE_INSTANCE
	}
	h, err := windows.CreateNamedPipe(name, mode, windows.PIPE_TYPE_BYTE|windows.PIPE_READMODE_BYTE|windows.PIPE_REJECT_REMOTE_CLIENTS, 5, 64<<10, 64<<10, 0, sa)
	if err == nil {
		p.first = false
	}
	return h, err
}

func (p *Pipe) Accept(ctx context.Context) (io.ReadWriteCloser, error) {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return nil, os.ErrClosed
	}
	h := p.pending
	p.accepting = true
	p.mu.Unlock()
	defer func() {
		p.mu.Lock()
		defer p.mu.Unlock()
		p.accepting = false
		if p.closed && p.pending != 0 {
			windows.CloseHandle(p.pending)
			p.pending = 0
		}
	}()
	event, err := windows.CreateEvent(nil, 1, 0, nil)
	if err != nil {
		return nil, err
	}
	defer windows.CloseHandle(event)
	op := windows.Overlapped{HEvent: event}
	var pinned runtime.Pinner
	pinned.Pin(&op)
	defer pinned.Unpin()
	err = windows.ConnectNamedPipe(h, &op)
	if errors.Is(err, windows.ERROR_IO_PENDING) {
		p.mu.Lock()
		if p.closed {
			windows.CancelIoEx(h, &op)
		}
		p.mu.Unlock()
		cancelDone := make(chan struct{})
		stop := context.AfterFunc(ctx, func() { windows.CancelIoEx(h, &op); close(cancelDone) })
		var bytes uint32
		err = windows.GetOverlappedResult(h, &op, &bytes, true)
		if !stop() {
			<-cancelDone
		}
	}
	if errors.Is(err, windows.ERROR_PIPE_CONNECTED) {
		err = nil
	}
	if errors.Is(err, windows.ERROR_NO_DATA) {
		windows.DisconnectNamedPipe(h)
		return nil, fmt.Errorf("%w: client disconnected before accept", errPeerRefused)
	}
	if err != nil {
		return nil, err
	}
	if err := authenticatePipe(h, p.standalone); err != nil {
		windows.DisconnectNamedPipe(h)
		return nil, fmt.Errorf("%w: %v", errPeerRefused, err)
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return nil, os.ErrClosed
	}
	// Retain at least one instance at every point; an empty namespace would
	// let another server race our next CreateNamedPipe.
	next, err := p.create()
	if err != nil {
		windows.DisconnectNamedPipe(h)
		if errors.Is(err, windows.ERROR_PIPE_BUSY) {
			return nil, fmt.Errorf("%w: four control connections are already active", errPeerRefused)
		}
		return nil, err
	}
	p.pending = next
	return os.NewFile(uintptr(h), p.name), nil
}

func authenticatePipe(h windows.Handle, standalone bool) error {
	var pid uint32
	proc := windows.NewLazySystemDLL("kernel32.dll").NewProc("GetNamedPipeClientProcessId")
	ok, _, err := proc.Call(uintptr(h), uintptr(unsafe.Pointer(&pid)))
	if ok == 0 {
		return err
	}
	process, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(process)
	var token windows.Token
	if err := windows.OpenProcessToken(process, windows.TOKEN_QUERY, &token); err != nil {
		return err
	}
	defer token.Close()
	user, err := token.GetTokenUser()
	if err != nil {
		return err
	}
	if user.User.Sid.IsWellKnown(windows.WinLocalSystemSid) {
		return nil
	}
	if standalone && token.IsElevated() {
		return nil
	}
	return fmt.Errorf("engine pipe refused client PID %d: SYSTEM required", pid)
}

func (p *Pipe) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return nil
	}
	p.closed = true
	windows.CancelIoEx(p.pending, nil)
	if !p.accepting {
		err := windows.CloseHandle(p.pending)
		p.pending = 0
		return err
	}
	// Accept owns the pending OVERLAPPED until cancellation completes. Closing
	// its handle here would make GetOverlappedResult race the final completion.
	return nil
}
