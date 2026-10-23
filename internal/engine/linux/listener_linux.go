package linux

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/AyoubAchour/net-switch/internal/engine/host"
	"golang.org/x/sys/unix"
)

type nativeListener struct {
	*net.UnixListener
	peerPID uint32
}

func (l *nativeListener) Accept(ctx context.Context) (io.ReadWriteCloser, error) {
	for {
		c, err := l.AcceptUnix()
		if err != nil {
			return nil, err
		}
		if err := checkPrivatePeer(c, l.peerPID); err != nil {
			c.Close()
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			continue
		}
		return c, nil
	}
}
func checkPrivatePeer(c *net.UnixConn, pid uint32) error {
	if err := peerRoot(c); err != nil {
		return err
	}
	raw, err := c.SyscallConn()
	if err != nil {
		return err
	}
	var cred *unix.Ucred
	var inner error
	if err := raw.Control(func(fd uintptr) { cred, inner = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED) }); err != nil {
		return err
	}
	if inner != nil {
		return inner
	}
	if pid != 0 && uint32(cred.Pid) != pid {
		return fmt.Errorf("private engine peer PID=%d expected=%d", cred.Pid, pid)
	}
	return nil
}
func ListenNative(socket string) (host.Listener, error) {
	if !filepath.IsAbs(socket) {
		return nil, errors.New("control socket must be absolute")
	}
	if err := os.MkdirAll(filepath.Dir(socket), 0700); err != nil {
		return nil, err
	}
	if err := checkSocketDirectory(filepath.Dir(socket)); err != nil {
		return nil, err
	}
	if st, err := os.Lstat(socket); err == nil {
		var s unix.Stat_t
		if err := unix.Lstat(socket, &s); err != nil {
			return nil, err
		}
		if st.Mode()&os.ModeSocket == 0 || s.Uid != 0 {
			return nil, errors.New("refusing to replace non-engine socket path")
		}
		if c, err := net.DialTimeout("unix", socket, 100*time.Millisecond); err == nil {
			c.Close()
			return nil, errors.New("another engine is listening")
		}
		if err := os.Remove(socket); err != nil {
			return nil, err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	l, err := net.ListenUnix("unix", &net.UnixAddr{Name: socket, Net: "unix"})
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(socket, 0600); err != nil {
		l.Close()
		return nil, err
	}
	return &nativeListener{UnixListener: l}, nil
}

func childSocket(nonce string) (string, error) {
	if b, err := hex.DecodeString(nonce); err != nil || len(b) != 16 {
		return "", errors.New("invalid private endpoint")
	}
	// A fixed 0600 pathname under the verified root-owned runtime directory
	// refuses unprivileged opens before accept. The native lifetime lock and
	// peer PID check fence generations; SIGKILL cannot accumulate stale names.
	return "/run/netswitch/engine-child.sock", nil
}
func ListenChild(nonce string, pid uint32) (host.Listener, error) {
	name, err := childSocket(nonce)
	if err != nil || pid == 0 {
		return nil, errors.New("invalid private endpoint identity")
	}
	l, err := ListenNative(name)
	if err != nil {
		return nil, err
	}
	l.(*nativeListener).peerPID = pid
	return l, nil
}
func DialChild(ctx context.Context, nonce string, pid uint32) (io.ReadWriteCloser, error) {
	name, err := childSocket(nonce)
	if err != nil || pid == 0 {
		return nil, errors.New("invalid private endpoint identity")
	}
	c, err := (&net.Dialer{}).DialContext(ctx, "unix", name)
	if err != nil {
		return nil, err
	}
	if err := checkPrivatePeer(c.(*net.UnixConn), pid); err != nil {
		c.Close()
		return nil, err
	}
	return c, nil
}
