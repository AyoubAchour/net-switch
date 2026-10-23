package lifecycle

import (
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	"github.com/AyoubAchour/net-switch/internal/engine/host"
	"github.com/AyoubAchour/net-switch/internal/engine/linux"
	"github.com/AyoubAchour/net-switch/internal/engine/supervisor"
	"github.com/AyoubAchour/net-switch/internal/localipc"
	"golang.org/x/sys/unix"
)

func startNativeChild(data, nonce string) (*nativeProcess, error) {
	// /proc/self/exe executes the running inode even if an update renamed it.
	cmd := exec.Command("/proc/self/exe", "native-child", data, nonce, strconv.Itoa(os.Getpid()))
	cmd.Env = nativeChildEnvironment()
	fd := -1
	cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL, PidFD: &fd}
	childIn, in, err := os.Pipe()
	if err != nil {
		return nil, err
	}
	defer childIn.Close()
	out, childOut, err := os.Pipe()
	if err != nil {
		in.Close()
		return nil, err
	}
	defer childOut.Close()
	stderr, childStderr, err := os.Pipe()
	if err != nil {
		in.Close()
		out.Close()
		return nil, err
	}
	defer childStderr.Close()
	// Own the parent ends ourselves: exec.Cmd.Wait must not close them before
	// the host drains a completion buffered while it was suspended.
	cmd.Stdin, cmd.Stdout, cmd.Stderr = childIn, childOut, childStderr
	started := make(chan error, 1)
	done := make(chan struct{})
	var result nativeResult
	var forced atomic.Bool
	go func() {
		// Pdeathsig follows the creating thread. Keep it alive until child exit.
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		if err := cmd.Start(); err != nil {
			started <- err
			return
		}
		started <- nil
		err := cmd.Wait()
		status, ok := cmd.ProcessState.Sys().(syscall.WaitStatus)
		if !ok {
			result.Err = errors.New("missing raw child status")
		} else if status.Signaled() {
			result.Code = uint32(128 + status.Signal())
			result.Forced = forced.Load() && status.Signal() == syscall.SIGKILL
		} else {
			result.Code = uint32(status.ExitStatus())
			if err != nil && result.Code == 0 {
				result.Err = err
			}
		}
		close(done)
	}()
	if err := <-started; err != nil {
		in.Close()
		out.Close()
		stderr.Close()
		return nil, err
	}
	p := &nativeProcess{pid: uint32(cmd.Process.Pid), input: in, output: out, stderr: stderr, resume: func() error { return nil }}
	p.alive = func() (bool, error) {
		fds := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
		n, err := unix.Poll(fds, 0)
		return n == 0 && err == nil, err
	}
	p.wait = func(ctx context.Context) (nativeResult, error) {
		select {
		case <-done:
			return result, result.Err
		case <-ctx.Done():
			return nativeResult{}, ctx.Err()
		}
	}
	p.kill = func() error {
		select {
		case <-done:
			return nil
		default:
		}
		forced.Store(true)
		err := unix.PidfdSendSignal(fd, unix.SIGKILL, nil, 0)
		if errors.Is(err, unix.ESRCH) {
			return nil
		}
		return err
	}
	var once sync.Once
	var closeErr error
	p.close = func() error {
		once.Do(func() {
			closeErr = p.kill()
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			_, err := p.wait(ctx)
			closeErr = errors.Join(closeErr, err, closeNativePipe(in), closeNativePipe(out), closeNativePipe(stderr), unix.Close(fd))
		})
		return closeErr
	}
	p.registrar = func(supervisor.Message) error { return errors.New("Linux child cannot register a Windows process") }
	if fd < 0 {
		cmd.Process.Kill()
		p.close()
		return nil, errors.New("native child requires pidfd support")
	}
	self, selfErr := os.Stat("/proc/self/exe")
	child, childErr := os.Stat("/proc/" + strconv.Itoa(cmd.Process.Pid) + "/exe")
	group, groupErr := os.ReadFile("/proc/self/cgroup")
	childGroup, childGroupErr := os.ReadFile("/proc/" + strconv.Itoa(cmd.Process.Pid) + "/cgroup")
	if err := errors.Join(selfErr, childErr, groupErr, childGroupErr); err != nil {
		p.close()
		return nil, err
	}
	if !os.SameFile(self, child) || string(group) != string(childGroup) {
		p.close()
		return nil, errors.New("native child image/cgroup mismatch")
	}
	return p, nil
}
func verifyNativeParent(pid uint32) error {
	var parentSignal int32
	_, _, errno := unix.Syscall6(unix.SYS_PRCTL, unix.PR_GET_PDEATHSIG, uintptr(unsafe.Pointer(&parentSignal)), 0, 0, 0, 0)
	if errno != 0 {
		return errno
	}
	if os.Geteuid() != 0 || uint32(os.Getppid()) != pid || parentSignal != int32(unix.SIGKILL) {
		return errors.New("native child lacks its supervisor lifetime guard")
	}
	return nil
}
func configureChildRegistrar(func(context.Context, supervisor.Message) error) error { return nil }
func listenNativePublic() (host.Listener, error) {
	return linux.ListenNative(localipc.DefaultPath("engine"))
}
func listenNativeChild(nonce string, pid uint32) (host.Listener, error) {
	return linux.ListenChild(nonce, pid)
}
func dialNativeChild(ctx context.Context, nonce string, pid uint32) (io.ReadWriteCloser, error) {
	return linux.DialChild(ctx, nonce, pid)
}
func nativeRefused(error) bool { return false }
func nativeAwake() time.Time   { return time.Now() }
func bindHealthSocket(raw syscall.RawConn, index int) error {
	var inner error
	err := raw.Control(func(fd uintptr) { inner = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_BINDTOIFINDEX, index) })
	return errors.Join(err, inner)
}

func connectHealthSocket(raw syscall.RawConn, port uint16) error {
	var inner error
	err := raw.Control(func(fd uintptr) {
		inner = unix.Connect(int(fd), &unix.SockaddrInet4{Addr: [4]byte{198, 18, 0, 2}, Port: int(port)})
	})
	return errors.Join(err, inner)
}
