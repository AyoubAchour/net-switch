package localipc

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"syscall"

	"golang.org/x/sys/unix"
)

type listener struct{ *net.UnixListener }

func DefaultPath(kind string) string {
	if kind == "status" {
		kind = "desktop"
	}
	return "/run/netswitch/" + kind + ".sock"
}

func credentials(c *net.UnixConn) (Peer, error) {
	raw, err := c.SyscallConn()
	if err != nil {
		return Peer{}, err
	}
	var cred *unix.Ucred
	var inner error
	err = raw.Control(func(fd uintptr) { cred, inner = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED) })
	if err != nil {
		return Peer{}, err
	}
	if inner != nil {
		return Peer{}, inner
	}
	return Peer{User: strconv.FormatUint(uint64(cred.Uid), 10), PID: uint32(cred.Pid)}, nil
}

func Listen(e Endpoint) (Listener, error) {
	// Socket activation owns the desktop pathname and its permissions.
	if e.Kind == "desktop" && os.Getenv("LISTEN_PID") == strconv.Itoa(os.Getpid()) && os.Getenv("LISTEN_FDS") == "1" {
		f := os.NewFile(3, "netswitch.socket")
		l, err := net.FileListener(f)
		f.Close()
		if err != nil {
			return nil, err
		}
		u, ok := l.(*net.UnixListener)
		if !ok {
			l.Close()
			return nil, errors.New("activation descriptor is not a unix socket")
		}
		u.SetUnlinkOnClose(false)
		return &listener{u}, nil
	}
	dir := filepath.Dir(e.Path)
	info, err := os.Lstat(dir)
	if err != nil {
		return nil, err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.IsDir() || stat.Uid != 0 || info.Mode().Perm()&0022 != 0 {
		return nil, errors.New("IPC directory must be root-owned and not writable by other users")
	}
	// Only remove a stale socket after proving nobody is listening. An engine
	// also holds its ownership lock before reaching this point.
	if info, err := os.Lstat(e.Path); err == nil {
		if info.Mode()&os.ModeSocket == 0 {
			return nil, errors.New("IPC path is not a socket")
		}
		c, err := net.Dial("unix", e.Path)
		if err == nil {
			c.Close()
			return nil, errors.New("IPC endpoint already active")
		}
		if !errors.Is(err, syscall.ECONNREFUSED) {
			return nil, err
		}
		if err := os.Remove(e.Path); err != nil {
			return nil, err
		}
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	u, err := net.ListenUnix("unix", &net.UnixAddr{Name: e.Path, Net: "unix"})
	if err != nil {
		return nil, err
	}
	mode := os.FileMode(0666)
	if e.Kind == "engine" {
		mode = 0600
	}
	if err := os.Chmod(e.Path, mode); err != nil {
		u.Close()
		return nil, err
	}
	return &listener{u}, nil
}
func (l *listener) Accept(ctx context.Context) (*Conn, error) {
	c, err := l.AcceptUnix()
	if err != nil {
		return nil, err
	}
	p, err := credentials(c)
	if err != nil {
		c.Close()
		return nil, fmt.Errorf("%w: %v", ErrPeer, err)
	}
	return &Conn{ReadWriteCloser: c, Peer: p}, nil
}
func Dial(ctx context.Context, e Endpoint) (*Conn, error) {
	raw, err := (&net.Dialer{}).DialContext(ctx, "unix", e.Path)
	if err != nil {
		return nil, err
	}
	c := raw.(*net.UnixConn)
	p, err := credentials(c)
	if err != nil || p.User != "0" {
		c.Close()
		return nil, fmt.Errorf("untrusted Net Switch server: peer=%s: %v", p.User, err)
	}
	return &Conn{ReadWriteCloser: c, Peer: p}, nil
}
