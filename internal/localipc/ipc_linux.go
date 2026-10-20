package localipc

import (
	"context"
	"encoding/binary"
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

func Unavailable(err error) bool {
	return errors.Is(err, os.ErrNotExist) || errors.Is(err, syscall.ECONNREFUSED)
}

func DefaultPath(kind string) string {
	if kind == "status" {
		kind = "desktop"
	} else if kind == "desktop" {
		kind = "owner"
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
	if e.Kind == "status" && os.Getenv("LISTEN_PID") == strconv.Itoa(os.Getpid()) && os.Getenv("LISTEN_FDS") == "1" {
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
	if e.Kind == "desktop" {
		mode = 0600
		// Keep root ownership for stale-listener probing after a crash. A
		// named ACL grants only the enrolled UID access; group zero gets none.
		if err := os.Chmod(e.Path, mode); err != nil {
			u.Close()
			return nil, err
		}
		if e.Owner != "" {
			uid, err := strconv.ParseUint(e.Owner, 10, 32)
			if err != nil {
				u.Close()
				return nil, err
			}
			if err := unix.Setxattr(e.Path, "system.posix_acl_access", ownerSocketACL(uint32(uid)), 0); err != nil {
				u.Close()
				return nil, err
			}
		}
		return &listener{u}, nil
	}
	if err := os.Chmod(e.Path, mode); err != nil {
		u.Close()
		return nil, err
	}
	return &listener{u}, nil
}

func ownerSocketACL(uid uint32) []byte {
	// Linux POSIX ACL xattr version 2; little-endian tag, permissions, ID.
	entries := []struct {
		tag, perm uint16
		id        uint32
	}{
		{1, 6, ^uint32(0)},  // root file owner
		{2, 6, uid},         // enrolled user
		{4, 0, ^uint32(0)},  // owning group
		{16, 6, ^uint32(0)}, // named-user mask
		{32, 0, ^uint32(0)}, // everyone else
	}
	b := make([]byte, 4+8*len(entries))
	binary.LittleEndian.PutUint32(b, 2)
	for i, e := range entries {
		o := 4 + i*8
		binary.LittleEndian.PutUint16(b[o:], e.tag)
		binary.LittleEndian.PutUint16(b[o+2:], e.perm)
		binary.LittleEndian.PutUint32(b[o+4:], e.id)
	}
	return b
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
