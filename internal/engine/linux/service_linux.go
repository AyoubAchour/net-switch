//go:build linux

package linux

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/AyoubAchour/net-switch/internal/engine"
	"github.com/AyoubAchour/net-switch/internal/engine/flows"
	"github.com/AyoubAchour/net-switch/internal/engine/protocol"
	"golang.org/x/sys/unix"
)

func peerRoot(c *net.UnixConn) error {
	raw, err := c.SyscallConn()
	if err != nil {
		return err
	}
	var cred *unix.Ucred
	var optionErr error
	err = raw.Control(func(fd uintptr) { cred, optionErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED) })
	err = errors.Join(err, optionErr)
	if err != nil {
		return err
	}
	if cred == nil || cred.Uid != 0 {
		return errors.New("engine control requires a root peer")
	}
	return nil
}

func checkSocketDirectory(path string) error {
	st, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !st.IsDir() || st.Mode().Perm()&0022 != 0 {
		return errors.New("control socket directory must not be writable by other users")
	}
	var directory unix.Stat_t
	if err := unix.Lstat(path, &directory); err != nil {
		return err
	}
	if directory.Uid != uint32(os.Geteuid()) {
		return errors.New("control socket directory belongs to another user")
	}
	return nil
}

func Serve(parent context.Context, socket, dir string, hooks func(*Platform, *engine.Engine, *protocol.Server)) error {
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	start, cancelStart := context.WithTimeout(ctx, 3*time.Second)
	p, err := New(start, dir)
	cancelStart()
	if err != nil {
		return err
	}
	// The recovery deadline is not the lifetime of forwarding.
	forwarding, cancelForwarding := context.WithCancel(ctx)
	defer cancelForwarding()
	p.ctx = forwarding
	if err := pingPermission(); err != nil {
		log.Print(err)
	}
	defer p.Close()
	e := engine.New(forwarding, engine.Dependencies{OpenTun: p.OpenTun, Routes: p, Dialer: p, Owners: p.Owners, Identities: p.Owners}, flows.Defaults(), flows.FileState{Path: filepath.Join(dir, "engine-state.json"), SyncParent: SyncDir})
	runtime := serviceRuntime{Engine: e, cancel: cancelForwarding}
	srv := protocol.New(runtime, e.Table, p)
	srv.Instance = p.Instance
	fatal := make(chan error, 1)
	p.Fatal = func(err error) {
		select {
		case fatal <- err:
		default:
		}
	}
	e.OnFatal = p.Fatal
	srv.OnCleanupFailure = func(err error) { p.Fatal(fmt.Errorf("control cleanup failed: %w", err)) }
	p.LineDown, p.AddressRemoved = lineEvents(e.Table)
	if hooks != nil {
		hooks(p, e, srv)
	}
	if !filepath.IsAbs(socket) {
		return errors.New("control socket must be absolute")
	}
	if err := os.MkdirAll(filepath.Dir(socket), 0700); err != nil {
		return err
	}
	if err := checkSocketDirectory(filepath.Dir(socket)); err != nil {
		return err
	}
	// Holding the lifetime flock proves the previous engine is gone. A stale
	// socket is removed only if root owns an actual socket, never a link/file.
	if st, err := os.Lstat(socket); err == nil {
		var s unix.Stat_t
		if err := unix.Lstat(socket, &s); err != nil {
			return err
		}
		if st.Mode()&os.ModeSocket == 0 || s.Uid != 0 {
			return errors.New("refusing to replace non-engine socket path")
		}
		if c, err := net.DialTimeout("unix", socket, 100*time.Millisecond); err == nil {
			c.Close()
			return errors.New("another engine is listening on the control socket")
		}
		if err := os.Remove(socket); err != nil {
			return err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	l, err := net.ListenUnix("unix", &net.UnixAddr{Name: socket, Net: "unix"})
	if err != nil {
		return err
	}
	defer l.Close()
	if err := os.Chmod(socket, 0600); err != nil {
		return err
	}
	stopListen := context.AfterFunc(ctx, func() { l.Close() })
	defer stopListen()
	go srv.RunLease(ctx)
	var clients sync.WaitGroup
	acceptErr := make(chan error, 1)
	acceptDone := make(chan struct{})
	go func() {
		defer close(acceptDone)
		for {
			c, err := l.AcceptUnix()
			if err != nil {
				acceptErr <- err
				return
			}
			if err := peerRoot(c); err != nil {
				log.Printf("refused engine peer: %v", err)
				c.Close()
				continue
			}
			clients.Go(func() {
				if err := srv.Serve(ctx, c); err != nil && ctx.Err() == nil && !errors.Is(err, context.Canceled) && !errors.Is(err, io.EOF) {
					log.Printf("control connection: %v", err)
				}
			})
		}
	}()
	log.Printf("engine %s ready at %s", p.Instance, socket)
	select {
	case <-parent.Done():
	case <-srv.Done():
	case err = <-fatal:
		log.Printf("routing stopped: %v", err)
	case err = <-acceptErr:
		if ctx.Err() == nil {
			err = fmt.Errorf("control listener: %w", err)
		}
	}
	// Remove capture even if the control transport failed. A nonpersistent
	// TUN disappearing on SIGKILL also removes its default route, leaving main.
	stop, cancelStop := context.WithTimeout(context.Background(), 10*time.Second)
	err = errors.Join(err, runtime.Stop(stop))
	cancelStop()
	cancel()
	l.Close()
	<-acceptDone
	clients.Wait()
	return err
}

// lineEvents closes what a line event took away (SYSTEM-DESIGN 5.7): every
// flow of a line that went down or moved, and, when a line loses an address,
// that line's flows from it: line and source together, since two routers
// commonly hand out the same 192.168.1.x to two lines.
func lineEvents(t *flows.Table) (down func(string), removed func(string, netip.Addr)) {
	return func(line string) { t.CloseFlows(flows.Selector{Line: line}, 0) },
		func(line string, addr netip.Addr) { t.CloseLineSource(line, addr) }
}

type serviceRuntime struct {
	*engine.Engine
	cancel context.CancelFunc
}

func (r serviceRuntime) Stop(ctx context.Context) error { r.cancel(); return r.Engine.Stop(ctx) }
