//go:build linux

package linux

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

func (o *Owners) WatchUDP(ctx context.Context, destroy func(netip.AddrPort, string), refresh func()) {
	for ctx.Err() == nil {
		_ = o.listenDestroy(ctx, destroy, refresh)
		if ctx.Err() != nil {
			return
		}
		refresh()
		select {
		case <-ctx.Done():
			return
		case <-time.After(100 * time.Millisecond):
		}
	}
}
func (o *Owners) listenDestroy(ctx context.Context, destroy func(netip.AddrPort, string), refresh func()) error {
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC|unix.SOCK_NONBLOCK, unix.NETLINK_SOCK_DIAG)
	if err != nil {
		return err
	}
	f := os.NewFile(uintptr(fd), "UDP destroy")
	defer f.Close()
	// Group numbers are 2 (INET_UDP_DESTROY) and 4 (INET6_UDP_DESTROY).
	if err := unix.Bind(fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK, Groups: 1<<1 | 1<<3}); err != nil {
		return err
	}
	stop := context.AfterFunc(ctx, func() { f.SetReadDeadline(time.Now()) })
	defer stop()
	refresh()
	b := make([]byte, 64<<10)
	for {
		n, err := readNetlink(f, b)
		if err != nil {
			if errors.Is(err, unix.ENOBUFS) {
				refresh()
				continue
			}
			return err
		}
		messages, err := syscall.ParseNetlinkMessage(b[:n])
		if err != nil {
			refresh()
			continue
		}
		for _, m := range messages {
			if m.Header.Type == unix.NLMSG_OVERRUN {
				refresh()
				continue
			}
			if m.Header.Type != 20 {
				continue
			}
			r, err := parseDiag(m.Data)
			if err != nil {
				refresh()
				continue
			}
			deliver := func() {
				// A wildcard app socket can back a NAT session using any local
				// address. The NAT handles wildcard destroys by cookie, never by port alone.
				destroy(r.local, r.generation())
				o.mu.Lock()
				delete(o.cache, r.cookie)
				group := time.Now().Before(o.ambiguousPorts[r.local.Port()])
				o.mu.Unlock()
				// A set generation is revalidated from live cookies. A delayed
				// member event therefore cannot close a replacement mapping.
				if group {
					refresh()
				}
			}
			if o.destroyFault != nil {
				o.destroyFault(ctx, r, deliver)
			} else {
				deliver()
			}
		}
	}
}
