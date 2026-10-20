package localipc

import (
	"context"
	"fmt"
	"os"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

const pipeClientRights = windows.FILE_READ_DATA | windows.FILE_WRITE_DATA |
	windows.FILE_READ_ATTRIBUTES | windows.FILE_WRITE_ATTRIBUTES | windows.SYNCHRONIZE

type listener struct {
	mu        sync.Mutex
	endpoint  Endpoint
	sd        *windows.SECURITY_DESCRIPTOR
	pending   windows.Handle
	closed    bool
	accepting bool
}

func DefaultPath(kind string) string {
	return `\\.\pipe\ProtectedPrefix\Administrators\NetSwitch\` + kind
}
func pipeDACL(e Endpoint) (string, error) {
	s := "D:P(A;;GA;;;SY)"
	// Do not use GW: it includes FILE_CREATE_PIPE_INSTANCE (0x4).
	if e.Kind != "engine" {
		s += "(A;;0x100183;;;BA)"
		if e.Kind == "status" {
			s += "(A;;0x100183;;;AU)"
		}
		if e.Owner != "" {
			if _, err := windows.StringToSid(e.Owner); err != nil {
				return "", err
			}
			s += "(A;;0x100183;;;" + e.Owner + ")"
		}
	}
	return s, nil
}
func (l *listener) create(first bool) (windows.Handle, error) {
	p, err := windows.UTF16PtrFromString(l.endpoint.Path)
	if err != nil {
		return 0, err
	}
	flags := uint32(windows.PIPE_ACCESS_DUPLEX | windows.FILE_FLAG_OVERLAPPED)
	if first {
		flags |= windows.FILE_FLAG_FIRST_PIPE_INSTANCE
	}
	sa := windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: l.sd}
	// The accept loop bounds active clients. A kernel instance ceiling here
	// would also count the next listener and client handles still held after
	// we reject a connection, letting a client exhaust and disable listening.
	return windows.CreateNamedPipe(p, flags, windows.PIPE_TYPE_BYTE|windows.PIPE_READMODE_BYTE|windows.PIPE_WAIT|windows.PIPE_REJECT_REMOTE_CLIENTS, windows.PIPE_UNLIMITED_INSTANCES, 65536, 65536, 0, &sa)
}
func Listen(e Endpoint) (Listener, error) {
	sddl, err := pipeDACL(e)
	if err != nil {
		return nil, err
	}
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return nil, err
	}
	l := &listener{endpoint: e, sd: sd}
	l.pending, err = l.create(true)
	if err != nil {
		return nil, err
	}
	return l, nil
}
func (l *listener) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.closed = true
	if l.pending != 0 {
		_ = windows.CancelIoEx(l.pending, nil)
		if !l.accepting {
			windows.CloseHandle(l.pending)
			l.pending = 0
		}
	}
	return nil
}
func (l *listener) Accept(ctx context.Context) (*Conn, error) {
	l.mu.Lock()
	if l.closed {
		l.mu.Unlock()
		return nil, os.ErrClosed
	}
	h := l.pending
	l.accepting = true
	l.mu.Unlock()
	defer func() {
		l.mu.Lock()
		defer l.mu.Unlock()
		l.accepting = false
		if l.closed && l.pending != 0 {
			windows.CloseHandle(l.pending)
			l.pending = 0
		}
	}()
	event, err := windows.CreateEvent(nil, 1, 0, nil)
	if err != nil {
		return nil, err
	}
	defer windows.CloseHandle(event)
	over := windows.Overlapped{HEvent: event}
	err = windows.ConnectNamedPipe(h, &over)
	if err == windows.ERROR_IO_PENDING {
		stop := context.AfterFunc(ctx, func() { _ = windows.CancelIoEx(h, &over) })
		var transferred uint32
		err = windows.GetOverlappedResult(h, &over, &transferred, true)
		stop()
	}
	// A client can connect and close between CreateNamedPipe and this wait.
	// Replace the listener while the old instance still protects its name.
	closedClient := err == windows.ERROR_NO_DATA
	if err != nil && err != windows.ERROR_PIPE_CONNECTED && !closedClient {
		windows.CloseHandle(h)
		l.mu.Lock()
		if l.pending == h {
			l.pending = 0
		}
		l.mu.Unlock()
		return nil, err
	}
	l.mu.Lock()
	if l.closed {
		l.pending = 0
		l.mu.Unlock()
		windows.CloseHandle(h)
		return nil, os.ErrClosed
	}
	// Keep an instance alive throughout replacement so a competing server
	// cannot take the name between clients.
	l.pending, err = l.create(false)
	if err != nil {
		l.pending = 0
	}
	l.mu.Unlock()
	if err != nil {
		windows.CloseHandle(h)
		return nil, err
	}
	if closedClient {
		windows.CloseHandle(h)
		return nil, fmt.Errorf("%w: client disconnected before accept", ErrPeer)
	}
	var pid uint32
	if err := windows.GetNamedPipeClientProcessId(h, &pid); err != nil {
		windows.CloseHandle(h)
		return nil, fmt.Errorf("%w: %v", ErrPeer, err)
	}
	p, err := processPeer(pid)
	if err != nil {
		windows.CloseHandle(h)
		return nil, fmt.Errorf("%w: %v", ErrPeer, err)
	}
	return &Conn{ReadWriteCloser: os.NewFile(uintptr(h), l.endpoint.Path), Peer: p}, nil
}

func processPeer(pid uint32) (Peer, error) {
	p, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return Peer{}, err
	}
	defer windows.CloseHandle(p)
	var token windows.Token
	if err := windows.OpenProcessToken(p, windows.TOKEN_QUERY, &token); err != nil {
		return Peer{}, err
	}
	defer token.Close()
	user, err := token.GetTokenUser()
	if err != nil {
		return Peer{}, err
	}
	var session, length uint32
	if err := windows.GetTokenInformation(token, windows.TokenSessionId, (*byte)(unsafe.Pointer(&session)), 4, &length); err != nil {
		return Peer{}, err
	}
	return Peer{User: user.User.Sid.String(), PID: pid, Session: session}, nil
}
func Dial(ctx context.Context, e Endpoint) (*Conn, error) {
	name, err := windows.UTF16PtrFromString(e.Path)
	if err != nil {
		return nil, err
	}
	var h windows.Handle
	for {
		h, err = windows.CreateFile(name, pipeClientRights, 0, nil, windows.OPEN_EXISTING,
			windows.FILE_FLAG_OVERLAPPED|windows.SECURITY_SQOS_PRESENT|windows.SECURITY_IDENTIFICATION, 0)
		if err != windows.ERROR_PIPE_BUSY {
			break
		}
		if err = Pause(ctx, 20*time.Millisecond); err != nil {
			return nil, err
		}
	}
	if err != nil {
		return nil, err
	}
	trusted := false
	defer func() {
		if !trusted {
			windows.CloseHandle(h)
		}
	}()
	var pid uint32
	if err := windows.GetNamedPipeServerProcessId(h, &pid); err != nil {
		return nil, err
	}
	manager, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CONNECT)
	if err != nil {
		return nil, err
	}
	defer windows.CloseServiceHandle(manager)
	serviceName, err := windows.UTF16PtrFromString(e.Service)
	if err != nil {
		return nil, err
	}
	service, err := windows.OpenService(manager, serviceName, windows.SERVICE_QUERY_STATUS)
	if err != nil {
		return nil, err
	}
	defer windows.CloseServiceHandle(service)
	var status windows.SERVICE_STATUS_PROCESS
	var needed uint32
	err = windows.QueryServiceStatusEx(service, windows.SC_STATUS_PROCESS_INFO, (*byte)(unsafe.Pointer(&status)), uint32(unsafe.Sizeof(status)), &needed)
	if err != nil {
		return nil, err
	}
	if status.ProcessId != pid || pid == 0 {
		return nil, fmt.Errorf("pipe PID %d is not the %s service PID %d", pid, e.Service, status.ProcessId)
	}
	trusted = true
	return &Conn{ReadWriteCloser: os.NewFile(uintptr(h), e.Path), Peer: Peer{User: "S-1-5-18", PID: pid}}, nil
}
