//go:build linux

// Package netns runs code inside a named network namespace (the ones `ip netns
// add` creates under /run/netns). A namespace belongs to an OS thread, so the
// work runs on a thread of its own that is thrown away afterwards: the rest of
// the program never sees another namespace.
package netns

import (
	"context"
	"fmt"
	"net"
	"runtime"
	"syscall"
)

// CLONE_NEWNET, the namespace type setns(2) is asked to enter.
const cloneNewnet = 0x40000000

// Path is where `ip netns` keeps a namespace.
func Path(name string) string { return "/run/netns/" + name }

// Enter moves the calling goroutine's thread into the namespace and keeps the
// goroutine locked to it for good. Use it only in a process about to exec.
func Enter(name string) error {
	runtime.LockOSThread()
	fd, err := syscall.Open(Path(name), syscall.O_RDONLY|syscall.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("open namespace %s: %w", name, err)
	}
	defer syscall.Close(fd)
	if _, _, errno := syscall.RawSyscall(sysSetns, uintptr(fd), cloneNewnet, 0); errno != 0 {
		return fmt.Errorf("enter namespace %s: %w", name, errno)
	}
	return nil
}

// Do runs fn inside the namespace and waits for it. Sockets fn creates stay in
// that namespace and can be used from anywhere afterwards.
func Do(name string, fn func() error) error {
	errc := make(chan error, 1)
	go func() {
		// The goroutine stays locked: when it ends, Go retires the thread
		// instead of reusing it in the wrong namespace.
		if err := Enter(name); err != nil {
			errc <- err
			return
		}
		errc <- fn()
	}()
	return <-errc
}

// Dialer returns a DialContext that opens connections inside the namespace,
// for example to reach an engine's local API from the harness.
func Dialer(name string) func(ctx context.Context, network, addr string) (net.Conn, error) {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		var conn net.Conn
		err := Do(name, func() error {
			var d net.Dialer
			c, err := d.DialContext(ctx, network, addr)
			conn = c
			return err
		})
		return conn, err
	}
}
