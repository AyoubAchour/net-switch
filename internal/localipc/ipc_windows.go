package localipc

import (
	"context"
	"errors"
	"fmt"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

const pipeClientRights = windows.FILE_READ_DATA | windows.FILE_WRITE_DATA |
	windows.FILE_READ_ATTRIBUTES | windows.FILE_WRITE_ATTRIBUTES | windows.SYNCHRONIZE

func Unavailable(err error) bool {
	return errors.Is(err, windows.ERROR_FILE_NOT_FOUND) || errors.Is(err, windows.ERROR_PIPE_BUSY)
}

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
	return s + "S:(ML;;NRNW;;;ME)", nil
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
	op, err := newPipeOp()
	if err != nil {
		return nil, err
	}
	defer op.close()
	err = windows.ConnectNamedPipe(h, &op.over)
	if err == windows.ERROR_IO_PENDING {
		_, err = op.wait(ctx, h)
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
		EarlyDisconnects.Add(1)
		windows.CloseHandle(h)
		return nil, fmt.Errorf("%w: client disconnected before accept", ErrPeer)
	}
	if err := readPipePreamble(ctx, h); err != nil {
		windows.CloseHandle(h)
		return nil, fmt.Errorf("%w: pipe identity handshake: %v", ErrPeer, err)
	}
	var pid uint32
	if err := windows.GetNamedPipeClientProcessId(h, &pid); err != nil {
		windows.CloseHandle(h)
		return nil, fmt.Errorf("%w: %v", ErrPeer, err)
	}
	p, err := pipePeer(h, pid)
	if err != nil {
		windows.CloseHandle(h)
		return nil, fmt.Errorf("%w: %v", ErrPeer, err)
	}
	return &Conn{ReadWriteCloser: os.NewFile(uintptr(h), l.endpoint.Path), Peer: p}, nil
}

// NPFS exposes the effective client token only after a read. Consume a single
// transport byte before impersonating; raw zero-access/idle opens get no owner
// slot and can hold this handshake for at most 250ms.
func readPipePreamble(ctx context.Context, h windows.Handle) error {
	ctx, cancel := context.WithTimeout(ctx, 250*time.Millisecond)
	defer cancel()
	op, err := newPipeOp()
	if err != nil {
		return err
	}
	defer op.close()
	// The byte count of an asynchronous read is only valid from the
	// completed OVERLAPPED; op.issued only satisfies x/sys's race build,
	// which dereferences the count pointer.
	err = windows.ReadFile(h, op.data[:], &op.issued, &op.over)
	if err != nil && err != windows.ERROR_IO_PENDING {
		return err
	}
	read, err := op.wait(ctx, h)
	if err != nil {
		return err
	}
	if read != 1 || op.data[0] != 0 {
		return fmt.Errorf("invalid pipe identity handshake")
	}
	return nil
}

// pipeOp is everything the kernel may write during one overlapped pipe call:
// the OVERLAPPED and the read buffer. Go can move a goroutine's stack while
// such a call is pending, so both live in one heap object that the waiting
// code and the cancel path reference until the call has completed or been
// cancelled and drained.
type pipeOp struct {
	over   windows.Overlapped
	data   [1]byte
	issued uint32
}

// newPipeOp is not inlined so the object always escapes to the heap, whatever
// the caller does with it. go build -gcflags=-m reports "new(pipeOp) escapes".
//
//go:noinline
func newPipeOp() (*pipeOp, error) {
	op := new(pipeOp)
	event, err := windows.CreateEvent(nil, 1, 0, nil)
	if err != nil {
		return nil, err
	}
	op.over.HEvent = event
	return op, nil
}

// wait blocks until the call issued with op on h completes. Cancelling ctx
// cancels only that call, and the wait still lasts until the kernel reports
// it finished, so op is never released while the kernel holds its address.
func (op *pipeOp) wait(ctx context.Context, h windows.Handle) (uint32, error) {
	finished := make(chan struct{})
	stop := context.AfterFunc(ctx, func() {
		defer close(finished)
		_ = windows.CancelIoEx(h, &op.over)
	})
	var transferred uint32
	err := windows.GetOverlappedResult(h, &op.over, &transferred, true)
	if !stop() {
		<-finished
	}
	runtime.KeepAlive(op)
	return transferred, err
}

func (op *pipeOp) close() { windows.CloseHandle(op.over.HEvent) }

var impersonatePipe = windows.NewLazySystemDLL("advapi32.dll").NewProc("ImpersonateNamedPipeClient")

func pipePeer(pipe windows.Handle, pid uint32) (peer Peer, err error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	ok, _, callErr := impersonatePipe.Call(uintptr(pipe))
	if ok == 0 {
		return Peer{}, callErr
	}
	defer func() {
		if revertErr := windows.RevertToSelf(); revertErr != nil {
			// A thread that cannot drop its borrowed identity must never run
			// further privileged work, nor return to Go's scheduler.
			fmt.Fprintln(os.Stderr, "cannot revert pipe impersonation:", revertErr)
			os.Exit(1)
		}
	}()
	var token windows.Token
	if err := windows.OpenThreadToken(windows.CurrentThread(), windows.TOKEN_QUERY, true, &token); err != nil {
		return Peer{}, err
	}
	defer token.Close()
	medium, err := mediumIntegrity(token)
	if err != nil {
		return Peer{}, err
	}
	if !medium {
		return Peer{}, fmt.Errorf("pipe client integrity is below medium")
	}
	return tokenPeer(token, pid)
}

// mediumIntegrity reports whether the token's mandatory label is at least
// medium. The owner's sandboxed or low-integrity processes stay below it.
func mediumIntegrity(token windows.Token) (bool, error) {
	var integrity [64]uint64
	var size uint32
	if err := windows.GetTokenInformation(token, windows.TokenIntegrityLevel, (*byte)(unsafe.Pointer(&integrity[0])), uint32(unsafe.Sizeof(integrity)), &size); err != nil {
		return false, err
	}
	label := (*windows.Tokenmandatorylabel)(unsafe.Pointer(&integrity[0]))
	if label.Label.Sid == nil {
		return false, nil
	}
	// A mandatory label is S-1-16-<level>. The string form avoids x/sys's
	// SubAuthority helpers, which turn a syscall result back into a pointer
	// into this Go buffer; the race build's checkptr rejects that.
	level, ok := strings.CutPrefix(label.Label.Sid.String(), "S-1-16-")
	if !ok {
		return false, fmt.Errorf("token integrity label is not a mandatory label SID")
	}
	rid, err := strconv.ParseUint(level, 10, 32)
	if err != nil {
		return false, fmt.Errorf("token integrity label %q: %w", level, err)
	}
	return rid >= 0x2000, nil // SECURITY_MANDATORY_MEDIUM_RID
}

// processPeerAt identifies a TCP client from its owning process. A process
// created after the connection reused the PID and is rejected. A process
// below medium integrity keeps its user SID behind LowIntegrity, so it is
// never mistaken for the owner, exactly as the pipes refuse it.
func processPeerAt(pid uint32, connectionCreated uint64) (Peer, error) {
	p, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return Peer{}, err
	}
	defer windows.CloseHandle(p)
	var created, exited, kernel, user windows.Filetime
	if err := windows.GetProcessTimes(p, &created, &exited, &kernel, &user); err != nil {
		return Peer{}, err
	}
	if connectionCreated == 0 || uint64(created.HighDateTime)<<32|uint64(created.LowDateTime) > connectionCreated {
		return Peer{}, ErrPeer
	}
	var token windows.Token
	if err := windows.OpenProcessToken(p, windows.TOKEN_QUERY, &token); err != nil {
		return Peer{}, err
	}
	defer token.Close()
	peer, err := tokenPeer(token, pid)
	if err != nil {
		return Peer{}, err
	}
	medium, err := mediumIntegrity(token)
	if err != nil {
		return Peer{}, err
	}
	if !medium {
		peer.User = LowIntegrity + peer.User
	}
	return peer, nil
}

func tokenPeer(token windows.Token, pid uint32) (Peer, error) {
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
	return dial(ctx, e, true)
}

// DialNativeEngine keeps the SCM process-identity check, but the native JSON
// transport has no M2 impersonation primer. A zero byte would corrupt hello.
func DialNativeEngine(ctx context.Context, e Endpoint) (*Conn, error) {
	if e.Kind != "engine" {
		return nil, errors.New("native dial is only for the engine endpoint")
	}
	return dial(ctx, e, false)
}

func dial(ctx context.Context, e Endpoint, primer bool) (*Conn, error) {
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
	f := os.NewFile(uintptr(h), e.Path)
	if primer {
		stop := context.AfterFunc(ctx, func() { f.Close() })
		_, err = f.Write([]byte{0})
		stop()
		if err != nil {
			f.Close()
			return nil, err
		}
	}
	return &Conn{ReadWriteCloser: f, Peer: Peer{User: "S-1-5-18", PID: pid}}, nil
}
