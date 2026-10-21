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

	"github.com/AyoubAchour/net-switch/internal/winhandle"
	"golang.org/x/sys/windows"
)

const EnginePipe = `\\.\pipe\ProtectedPrefix\Administrators\NetSwitch\engine`

var errPeerRefused = errors.New("engine pipe peer refused")

type Pipe struct {
	name       string
	standalone bool
	mu         sync.Mutex
	pending    winhandle.Owner
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

func (p *Pipe) create() (winhandle.Owner, error) {
	acl := "D:P(A;;GA;;;SY)"
	if p.standalone {
		acl = "D:P(A;;GA;;;SY)(A;;GRGW;;;BA)"
	}
	sa, err := security(acl)
	if err != nil {
		return winhandle.Owner{}, err
	}
	name, err := windows.UTF16PtrFromString(p.name)
	if err != nil {
		return winhandle.Owner{}, err
	}
	mode := uint32(windows.PIPE_ACCESS_DUPLEX | windows.FILE_FLAG_OVERLAPPED)
	if p.first {
		mode |= windows.FILE_FLAG_FIRST_PIPE_INSTANCE
	}
	h, err := windows.CreateNamedPipe(name, mode, windows.PIPE_TYPE_BYTE|windows.PIPE_READMODE_BYTE|windows.PIPE_REJECT_REMOTE_CLIENTS, 5, 64<<10, 64<<10, 0, sa)
	if err == nil {
		p.first = false
		return winhandle.Open(h, "engine pipe instance open"), nil
	}
	return winhandle.Owner{}, err
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
		if p.closed && !p.pending.IsZero() {
			p.pending.HandleClose("engine pipe cancelled accept close")
			p.pending = winhandle.Owner{}
		}
	}()
	event, err := windows.CreateEvent(nil, 1, 0, nil)
	if err != nil {
		return nil, err
	}
	eventOwner := winhandle.Open(event, "engine pipe accept event open")
	defer eventOwner.HandleClose("engine pipe accept event close")
	op := windows.Overlapped{HEvent: eventOwner.Handle("engine pipe accept event")}
	var pinned runtime.Pinner
	pinned.Pin(&op)
	defer pinned.Unpin()
	err = windows.ConnectNamedPipe(h.Handle("engine pipe accept"), &op)
	if errors.Is(err, windows.ERROR_IO_PENDING) {
		p.mu.Lock()
		if p.closed {
			windows.CancelIoEx(h.Handle("engine pipe accept already closed"), &op)
		}
		p.mu.Unlock()
		cancelDone := make(chan struct{})
		stop := context.AfterFunc(ctx, func() { windows.CancelIoEx(h.Handle("engine pipe accept context cancel"), &op); close(cancelDone) })
		var bytes uint32
		err = windows.GetOverlappedResult(h.Handle("engine pipe accept completion"), &op, &bytes, true)
		if !stop() {
			<-cancelDone
		}
	}
	if errors.Is(err, windows.ERROR_PIPE_CONNECTED) {
		err = nil
	}
	if errors.Is(err, windows.ERROR_NO_DATA) {
		windows.DisconnectNamedPipe(h.Handle("engine pipe early disconnect"))
		return nil, fmt.Errorf("%w: client disconnected before accept", errPeerRefused)
	}
	if err != nil {
		return nil, err
	}
	if err := authenticatePipe(h.Handle("engine pipe authenticate"), p.standalone); err != nil {
		windows.DisconnectNamedPipe(h.Handle("engine pipe refused peer"))
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
		windows.DisconnectNamedPipe(h.Handle("engine pipe replacement failure"))
		if errors.Is(err, windows.ERROR_PIPE_BUSY) {
			return nil, fmt.Errorf("%w: four control connections are already active", errPeerRefused)
		}
		return nil, err
	}
	p.pending = next
	return newPipeConn(h, p.name)
}

// pipeConn is one connected engine pipe instance. The protocol server reads
// and writes it at the same time, one operation per direction.
//
// It does its own event-based overlapped I/O instead of using os.File. Go
// 1.27.3's internal/poll updates a per-file offset after every pipe Read and
// Write without synchronization, so a full-duplex pipe is a data race (seen
// by the race detector in TestTerminalLossCancelsRealEnginePipeBlockedWrite,
// run 39559440093). Go fixed it upstream in f4ac29c3c7 ("don't track offsets
// for Windows pipes", 2026-09-11), after our pinned release.
//
// The handle is never associated with Go's completion port; each direction
// waits on its own event. Close cancels both directions and waits for them to
// finish before the handle is closed, so no OVERLAPPED or buffer is released
// while the kernel may still use it.
type pipeConn struct {
	h           winhandle.Owner
	name        string
	read, write pipeOp
	readMu      sync.Mutex // one read at a time
	writeMu     sync.Mutex // one write at a time
	mu          sync.Mutex // closed, and issuing I/O against Close's cancel
	closed      bool
	active      sync.WaitGroup
	closeOnce   sync.Once
	closeErr    error
	readEvent   winhandle.Owner
	writeEvent  winhandle.Owner
}

// pipeOp is one direction's OVERLAPPED. It lives inside the heap pipeConn
// and is reused only after the previous operation in that direction finished.
type pipeOp struct {
	o windows.Overlapped
}

func newPipeConn(h winhandle.Owner, name string) (io.ReadWriteCloser, error) {
	c := &pipeConn{h: h, name: name}
	for _, event := range []*winhandle.Owner{&c.readEvent, &c.writeEvent} {
		e, err := windows.CreateEvent(nil, 1, 0, nil)
		if err != nil {
			c.closeEvents()
			windows.DisconnectNamedPipe(h.Handle("engine pipe event failure"))
			return nil, errors.Join(fmt.Errorf("engine pipe event: %w", err), h.HandleClose("engine pipe event failure close"))
		}
		*event = winhandle.Open(e, "engine pipe connection event open")
	}
	return c, nil
}

func (c *pipeConn) closeEvents() {
	for _, event := range []*winhandle.Owner{&c.readEvent, &c.writeEvent} {
		if !event.IsZero() {
			event.HandleClose("engine pipe connection event close")
			*event = winhandle.Owner{}
		}
	}
}

func (c *pipeConn) Read(b []byte) (int, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()
	n, err := c.transfer(&c.read, c.readEvent, b, false)
	switch {
	case errors.Is(err, windows.ERROR_BROKEN_PIPE), errors.Is(err, windows.ERROR_HANDLE_EOF):
		// The client closed its end; os.File reports the same as EOF.
		err = io.EOF
	case err != nil:
		err = &os.PathError{Op: "read", Path: c.name, Err: err}
	}
	return n, err
}

func (c *pipeConn) Write(b []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	written := 0
	for written < len(b) {
		n, err := c.transfer(&c.write, c.writeEvent, b[written:], true)
		written += n
		if err != nil {
			return written, &os.PathError{Op: "write", Path: c.name, Err: err}
		}
		if n == 0 {
			return written, &os.PathError{Op: "write", Path: c.name, Err: io.ErrShortWrite}
		}
	}
	return written, nil
}

// transfer submits one overlapped read or write and waits for it. b must
// stay put until the kernel is done with it, so it is pinned (and therefore
// heap-allocated) for the whole operation, including a cancelled one.
func (c *pipeConn) transfer(op *pipeOp, event winhandle.Owner, b []byte, write bool) (int, error) {
	if len(b) == 0 {
		return 0, nil
	}
	if len(b) > 1<<30 {
		b = b[:1<<30]
	}
	var pinned runtime.Pinner
	pinned.Pin(&b[0])
	defer pinned.Unpin()
	// Submit under mu so Close's CancelIoEx either sees this operation or
	// this operation sees closed. It never blocks: the handle is overlapped.
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return 0, os.ErrClosed
	}
	c.active.Add(1)
	defer c.active.Done()
	ev := event.Handle("engine pipe operation event")
	windows.ResetEvent(ev)
	op.o = windows.Overlapped{HEvent: ev}
	h := c.h.Handle("engine pipe operation")
	var err error
	if write {
		err = windows.WriteFile(h, b, nil, &op.o)
	} else {
		err = windows.ReadFile(h, b, nil, &op.o)
	}
	c.mu.Unlock()
	if err != nil && !errors.Is(err, windows.ERROR_IO_PENDING) {
		return 0, err
	}
	// Inline success and pending completion both report through the same
	// OVERLAPPED. Wait for the final count; after cancellation this returns
	// ERROR_OPERATION_ABORTED once the kernel has released b and op.
	var done uint32
	err = windows.GetOverlappedResult(h, &op.o, &done, true)
	if err != nil && errors.Is(err, windows.ERROR_OPERATION_ABORTED) {
		c.mu.Lock()
		closed := c.closed
		c.mu.Unlock()
		if closed {
			err = os.ErrClosed
		}
	}
	return int(done), err
}

// Close cancels any read or write in progress, waits until the kernel has
// finished with both, and then closes the pipe instance.
func (c *pipeConn) Close() error {
	c.closeOnce.Do(func() {
		c.mu.Lock()
		c.closed = true
		cancelErr := windows.CancelIoEx(c.h.Handle("engine pipe connection cancel"), nil)
		c.mu.Unlock()
		if errors.Is(cancelErr, windows.ERROR_NOT_FOUND) {
			cancelErr = nil // nothing was in flight
		}
		c.active.Wait()
		c.closeEvents()
		c.closeErr = errors.Join(cancelErr, c.h.HandleClose("engine pipe connection close"))
	})
	return c.closeErr
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
	processOwner := winhandle.Open(process, "pipe client process open")
	defer processOwner.HandleClose("pipe client process close")
	var token windows.Token
	if err := windows.OpenProcessToken(processOwner.Handle("pipe client token open"), windows.TOKEN_QUERY, &token); err != nil {
		return err
	}
	tokenOwner := winhandle.Open(windows.Handle(token), "pipe client token")
	defer tokenOwner.CloseGo("pipe client token close", token.Close)
	tokenOwner.Handle("pipe client token identity")
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
	windows.CancelIoEx(p.pending.Handle("engine pipe listener cancel"), nil)
	if !p.accepting {
		err := p.pending.HandleClose("engine pipe listener close")
		p.pending = winhandle.Owner{}
		return err
	}
	// Accept owns the pending OVERLAPPED until cancellation completes. Closing
	// its handle here would make GetOverlappedResult race the final completion.
	return nil
}
